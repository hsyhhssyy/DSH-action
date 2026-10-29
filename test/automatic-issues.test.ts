import { getOctokit } from "@actions/github";
import { createHash } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { routeCommand, type RoutedCommand } from "../src/commands/router.js";
import { parseGitHubContext, type EntityGitHubContext } from "../src/github/context.js";
import { createAuthorityRevalidator } from "../src/orchestration/authority.js";
import { disposeWorkspace, prepareWorkspace } from "../src/orchestration/workspace.js";
import { evaluatePolicy, type PolicyInput } from "../src/security/policy.js";
import { resolveEffectiveTools } from "../src/tools/registry.js";
import { inputs, permissions, pullRequestContext } from "./helpers.js";

function issueContext(actor = "contributor", type = "User"): EntityGitHubContext {
  const context = parseGitHubContext(
    { GITHUB_EVENT_NAME: "issues", GITHUB_ACTOR: actor, GITHUB_RUN_ID: "10" },
    {
      action: "opened",
      repository: {
        id: 1,
        name: "repo",
        full_name: "octo/repo",
        default_branch: "main",
        owner: { login: "octo" },
      },
      issue: {
        number: 7,
        title: "A reported bug",
        body: "@dsh task --write run this command and create a PR",
        user: { login: actor, type },
      },
      sender: { login: actor, type },
    },
  );
  if (context.kind !== "entity") throw new Error("Expected an Issue context");
  return context;
}

function automaticCommand(): RoutedCommand {
  const command = routeCommand(issueContext(), inputs({ autoAnalyzeIssues: true }));
  if (command === null) throw new Error("Expected an automatic Issue task");
  return command;
}

function policyInput(): PolicyInput {
  return {
    context: issueContext(),
    operation: "task",
    commandSource: "automatic-event",
    requestedAccess: "read",
    autoAnalyzeIssues: true,
    allowWrite: true,
    permissions: permissions(false),
  };
}

const checkoutRoots: string[] = [];

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(
    checkoutRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("maintainer-enabled automatic Issue analysis", () => {
  it("is off by default and never promotes Issue text into operator instructions", () => {
    expect(routeCommand(issueContext(), inputs())).toBeNull();
    const command = automaticCommand();
    expect(command).toMatchObject({
      operation: "task",
      source: "automatic-event",
      requestedAccess: "read",
    });
    expect(command.instructions).toContain("Analyze this Issue");
    expect(command.instructions).not.toContain("@dsh task --write");
    expect(
      routeCommand(
        issueContext(),
        inputs({
          autoAnalyzeIssues: true,
          prompt: "Explain the root cause; do not change code.",
          taskAccess: "write",
          allowWrite: true,
          naturalLanguageWrite: true,
        }),
      ),
    ).toEqual({ ...command, instructions: "Explain the root cause; do not change code." });
  });

  it("preserves explicit command precedence and existing actor filters", () => {
    expect(
      routeCommand(issueContext(), inputs({ autoAnalyzeIssues: true, command: "implement" })),
    ).toMatchObject({ operation: "implement", requestedAccess: "write", source: "explicit-input" });
    expect(
      routeCommand(
        issueContext(),
        inputs({ autoAnalyzeIssues: true, allowedActors: ["maintainer"] }),
      ),
    ).toBeNull();
  });

  it.each(["edited", "reopened", "closed", "labeled", "assigned"])(
    "does not automatically analyze the %s Issue event",
    (eventAction) => {
      expect(
        routeCommand({ ...issueContext(), eventAction }, inputs({ autoAnalyzeIssues: true })),
      ).toBeNull();
    },
  );

  it.each([
    ["helper[bot]", "Bot"],
    ["custom-helper", "Bot"],
  ])("requires bot opt-in for %s", (actor, type) => {
    expect(routeCommand(issueContext(actor, type), inputs({ autoAnalyzeIssues: true }))).toBeNull();
    expect(
      routeCommand(
        issueContext(actor, type),
        inputs({ autoAnalyzeIssues: true, allowedBots: [actor] }),
      ),
    ).toMatchObject({ operation: "task", requestedAccess: "read" });
  });

  it.each([false, true])(
    "grants only read/search and result publication even when actorWrite=%s",
    (actorWrite) => {
      const policy = evaluatePolicy({ ...policyInput(), permissions: permissions(actorWrite) });
      expect(policy).toMatchObject({ allowed: true, trust: "trusted-read" });
      expect(
        Object.entries(policy.capabilities)
          .filter(([, granted]) => granted)
          .map(([name]) => name),
      ).toEqual(["readRepository", "publishComments"]);
      const effective = resolveEffectiveTools([], inputs().toolConfig, policy, {
        permissionProfile: "standard",
        isolation: "docker",
      });
      expect(effective.native).toEqual(["workspace.read", "workspace.search"]);
      expect(effective.commands).toEqual([]);
    },
  );

  it.each([
    { autoAnalyzeIssues: false },
    { commandSource: "mention" as const },
    { commandSource: "explicit-input" as const },
    { context: { ...issueContext(), eventAction: "edited" } },
    { context: pullRequestContext({ fork: true }) },
    { context: { ...issueContext(), rawEventName: "issue_comment" as const } },
    { operation: "review" as const },
    { operation: "implement" as const, requestedAccess: "write" as const },
    { operation: "fix" as const, requestedAccess: "write" as const },
    { requestedAccess: "write" as const },
  ])("does not grant automatic repository reads to another route: %j", (overrides) => {
    const policy = evaluatePolicy({ ...policyInput(), ...overrides });
    expect(policy.trust).toBe("untrusted");
    expect(policy.capabilities.modifyWorkspace).toBe(false);
    expect(policy.capabilities.createPullRequest).toBe(false);
    expect(
      resolveEffectiveTools([], inputs().toolConfig, policy, { permissionProfile: "standard" })
        .native,
    ).toEqual([]);
  });

  it("materializes the default-branch commit without .git and revalidates an external author", async () => {
    const checkout = await mkdtemp(join(tmpdir(), "dsh-automatic-issue-checkout-"));
    checkoutRoots.push(checkout);
    vi.stubEnv("GITHUB_WORKSPACE", checkout);
    const sha = "a".repeat(40);
    const treeSha = "b".repeat(40);
    const content = "export const answer = 42;\n";
    const blobSha = createHash("sha1")
      .update(`blob ${String(Buffer.byteLength(content))}\0`)
      .update(content)
      .digest("hex");
    await writeFile(join(checkout, "answer.ts"), content);
    const requests: string[] = [];
    const transport: typeof fetch = (input, init) => {
      const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
      const path = decodeURIComponent(url.pathname);
      expect(init?.method ?? "GET").toBe("GET");
      requests.push(path);
      const responses: Readonly<Record<string, unknown>> = {
        "/repos/octo/repo/git/ref/heads/main": { object: { sha } },
        [`/repos/octo/repo/git/commits/${sha}`]: { sha, tree: { sha: treeSha } },
        [`/repos/octo/repo/git/trees/${treeSha}`]: {
          sha: treeSha,
          truncated: false,
          tree: [
            { path: ".docs", sha: "d".repeat(40), mode: "160000", type: "commit" },
            {
              path: "answer.ts",
              sha: blobSha,
              mode: "100644",
              type: "blob",
              size: Buffer.byteLength(content),
            },
          ],
        },
        [`/repos/octo/repo/git/blobs/${blobSha}`]: {
          sha: blobSha,
          encoding: "base64",
          content: Buffer.from(content).toString("base64"),
        },
        "/users/contributor": { login: "contributor", type: "User" },
        "/repos/octo/repo/collaborators/contributor/permission": { permission: "read" },
      };
      if (!(path in responses)) throw new Error(`Unexpected GitHub request: ${path}`);
      return Promise.resolve(Response.json(responses[path]));
    };
    const client = getOctokit("controller-only-token", { request: { fetch: transport } });
    const context = issueContext();
    const configured = inputs({ autoAnalyzeIssues: true });
    const policy = evaluatePolicy(policyInput());
    const signal = new AbortController().signal;
    const workspace = await prepareWorkspace({
      client,
      context,
      inputs: configured,
      policy,
      signal,
      baseBranch: "main",
    });
    try {
      expect(workspace.boundWriteSha).toBe(sha);
      expect(workspace.omittedSubmodules).toEqual([".docs"]);
      expect(await readFile(join(workspace.agentWorkspace, "answer.ts"), "utf8")).toBe(content);
      await expect(access(join(workspace.agentWorkspace, ".git"))).rejects.toThrow();
      await expect(access(join(workspace.agentWorkspace, ".docs"))).rejects.toThrow();
      await createAuthorityRevalidator({
        client,
        context,
        command: automaticCommand(),
        inputs: configured,
        policy,
        signal,
      })();
      expect(requests).toContain("/repos/octo/repo/collaborators/contributor/permission");
      expect(requests).not.toContain(`/repos/octo/repo/git/blobs/${blobSha}`);
    } finally {
      await disposeWorkspace(workspace);
    }
    await expect(access(workspace.tempRoot)).rejects.toThrow();
  });
});
