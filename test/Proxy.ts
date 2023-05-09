import { beforeEach, expect, describe, test } from "@jest/globals";
import Proxy from "../src/Proxy";
import { mock, mockDeep } from "jest-mock-extended";
import {
  CloudFrontCustomOrigin,
  CloudFrontRequest,
  CloudFrontRequestEvent,
  CloudFrontResponse,
} from "aws-lambda";
import { SignJWT, jwtVerify } from "jose";
import cookie from "cookie";
import { OAuthApp } from "@octokit/oauth-app";

// We need @ts-ignore because the types for jest-mock-extended are not correct.
/* eslint-disable @typescript-eslint/ban-ts-comment */

const makeRequest = (
  request: Partial<CloudFrontRequest>
): CloudFrontRequest => {
  return {
    clientIp: "none",
    method: "GET",
    querystring: "",
    uri: "",
    headers: {},
    origin: {
      custom: {} as CloudFrontCustomOrigin,
    },
    ...request,
  };
};

const makeEvent = (
  request: Partial<CloudFrontRequest>
): CloudFrontRequestEvent => {
  return {
    Records: [
      {
        cf: {
          request: makeRequest(request),
          config: {
            distributionId: "none",
            distributionDomainName: "none",
            eventType: "viewer-request",
            requestId: "none",
          },
        },
      },
    ],
  };
};
function assertIsResponse(
  response: unknown
): asserts response is CloudFrontResponse {
  expect(response).toHaveProperty("status");
}

function assertIsRequest(
  response: unknown
): asserts response is CloudFrontRequest {
  expect(response).toHaveProperty("uri");
}

describe("Request interception", function () {
  let proxy: Proxy;
  let app: OAuthApp;
  beforeEach(function () {
    app = mockDeep<OAuthApp>();
    proxy = new Proxy(app, {
      baseUrl: "https://foo.bar",
      hashKey: "foo",
      logger: mock<typeof console>(),
    });
  });

  test("Redirects unauthenticated requests to login", async function () {
    const response = await proxy.handleEvent(makeEvent({ uri: "/foo" }));
    assertIsResponse(response);
    expect(response.status).toEqual("302");
    expect(response.headers.location[0].value).toEqual(
      "/oauth/login?destination=%2Ffoo"
    );
  });

  test("Allows authenticated requests", async function () {
    const token = await new SignJWT({ bar: "baz" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("12h")
      .sign(new TextEncoder().encode("foo"));

    const event = makeEvent({
      uri: "/foo",
      headers: {
        cookie: [{ key: "cookie", value: cookie.serialize("_auth", token) }],
      },
    });
    const response = await proxy.handleEvent(event);
    assertIsRequest(response);
  });

  test("Blocks requests with invalid tokens", async function () {
    const token = await new SignJWT({ bar: "baz" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("12h")
      .sign(new TextEncoder().encode("invalid"));

    const event = makeEvent({
      uri: "/foo",
      headers: {
        cookie: [{ key: "cookie", value: cookie.serialize("_auth", token) }],
      },
    });
    const response = await proxy.handleEvent(event);
    assertIsResponse(response);
  });
  test("Blocks requests with expired tokens", async function () {
    const token = await new SignJWT({ bar: "baz" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime(-1)
      .sign(new TextEncoder().encode("valid"));

    const event = makeEvent({
      uri: "/foo",
      headers: {
        cookie: [{ key: "cookie", value: cookie.serialize("_auth", token) }],
      },
    });
    const response = await proxy.handleEvent(event);
    assertIsResponse(response);
  });
});

describe("Login endpoint", function () {
  test("Responds to request for login URL by  redirecting to authorize url", async function () {
    const app = mockDeep<OAuthApp>();
    // @ts-ignore - see https://github.com/marchaos/jest-mock-extended/issues/114
    app.getWebFlowAuthorizationUrl.mockReturnValue({
      url: "https://auth.me/authorize?redirect_uri=https%3A%2F%2Ffoo.bar%2Fauth%2Fcallback&state=%2F",
    });
    const proxy = new Proxy(app, {
      baseUrl: "https://foo.bar",
      hashKey: "valid",
      logger: dummyLogger,
    });
    const response = await proxy.handleEvent(
      makeEvent({
        uri: "/oauth/login",
        headers: {},
      })
    );
    assertIsResponse(response);
    expect(response.status).toEqual("302");
    expect(response.headers.location[0].value).toEqual(
      "https://auth.me/authorize?redirect_uri=https%3A%2F%2Ffoo.bar%2Fauth%2Fcallback&state=%2F"
    );
    expect(app.getWebFlowAuthorizationUrl).toHaveBeenLastCalledWith({
      redirectUrl: "https://foo.bar/oauth/callback?destination=/",
      scopes: ["openid"],
      state: expect.any(String),
    });
  });
  test("Uses custom scopes in redirect URL", async function () {
    const app = mockDeep<OAuthApp>();

    // @ts-ignore - see https://github.com/marchaos/jest-mock-extended/issues/114
    app.getWebFlowAuthorizationUrl.mockReturnValue({
      url: "https://auth.me/authorize?redirect_uri=https%3A%2F%2Ffoo.bar%2Fauth%2Fcallback&state=%2F",
    });
    const proxy = new Proxy(app, {
      baseUrl: "https://foo.bar",
      hashKey: "valid",
      logger: dummyLogger,
      scopes: ["foo", "bar"],
    });
    await proxy.handleEvent(
      makeEvent({
        uri: "/oauth/login",
        headers: {},
      })
    );
    expect(app.getWebFlowAuthorizationUrl).toHaveBeenLastCalledWith({
      redirectUrl: "https://foo.bar/oauth/callback?destination=/",
      scopes: ["foo", "bar"],
      state: expect.any(String),
    });
  });
  test("Sets a state cookie on redirecting to authorize url", async function () {
    const app = mockDeep<OAuthApp>();
    // @ts-ignore - see https://github.com/marchaos/jest-mock-extended/issues/114
    app.getWebFlowAuthorizationUrl.mockReturnValue({
      url: "https://auth.me/authorize?redirect_uri=https%3A%2F%2Ffoo.bar%2Fauth%2Fcallback&state=%2F",
    });
    const proxy = new Proxy(app, {
      baseUrl: "https://foo.bar",
      hashKey: "valid",
      logger: mock<typeof console>(),
    });
    const response = await proxy.handleEvent(
      makeEvent({
        uri: "/oauth/login",
        headers: {},
      })
    );
    assertIsResponse(response);
    expect(response.headers["set-cookie"]).toStrictEqual([
      expect.objectContaining({
        key: "Set-Cookie",
        value: expect.stringContaining("_auth.state="),
      }),
    ]);
  });
});

describe("Logout endpoint", function () {
  let proxy: Proxy;
  beforeEach(function () {
    const app = mockDeep<OAuthApp>();
    proxy = new Proxy(app, {
      baseUrl: "https://foo.bar",
      hashKey: "foo",
      logger: mock<typeof console>(),
    });
  });
  test("Redirects to homepage on logout without destination", async function () {
    const response = await proxy.handleEvent(
      makeEvent({
        uri: "/oauth/logout",
        headers: {},
      })
    );
    assertIsResponse(response);
    expect(response.status).toEqual("302");
    expect(response.headers.location[0].value).toEqual("/");
  });

  test("Redirects to destination on logout with destination", async function () {
    const response = await proxy.handleEvent(
      makeEvent({
        uri: "/oauth/logout",
        querystring: "destination=%2Ffoo",
        headers: {},
      })
    );
    assertIsResponse(response);
    expect(response.status).toEqual("302");
    expect(response.headers.location[0].value).toEqual("/foo");
  });

  test("Unsets the auth cookie on logout", async function () {
    const response = await proxy.handleEvent(
      makeEvent({
        uri: "/oauth/logout",
        headers: {},
      })
    );
    assertIsResponse(response);
    expect(response.headers["set-cookie"][0].value).toContain("; HttpOnly");
    expect(response.headers["set-cookie"][0].value).toContain("; Secure");
    const parsedCookie = cookie.parse(response.headers["set-cookie"][0].value);
    expect(parsedCookie._auth).toEqual("");
  });
});

describe("Callback endpoint", function () {
  let proxy: Proxy;
  let app: OAuthApp;
  beforeEach(function () {
    app = mockDeep<OAuthApp>();
    // @ts-ignore
    app.createToken.mockImplementation(async (opts) => {
      if (opts.code === "letmein") {
        return { authentication: { token: "foo" } };
      } else {
        throw new Error("Invalid code");
      }
    });
    proxy = new Proxy(app, {
      baseUrl: "https://foo.bar",
      hashKey: "foo",
      logger: mock<typeof console>(),
    });
  });

  test("Responds to callback for valid code by redirecting to destination", async function () {
    const response = await proxy.handleEvent(
      makeEvent({
        uri: "/oauth/callback",
        querystring: "code=letmein&destination=%2Ffoo&state=foostate",
        headers: {
          cookie: [{ key: "Cookie", value: "_auth.state=foostate" }],
        },
      })
    );
    assertIsResponse(response);
    expect(response.status).toEqual("302");
    expect(response.headers.location[0].value).toEqual("/foo");
  });

  test("Responds to callback for valid code by setting an auth cookie", async function () {
    const response = await proxy.handleEvent(
      makeEvent({
        uri: "/oauth/callback",
        querystring: "code=letmein&state=foostate",
        headers: {
          cookie: [{ key: "Cookie", value: "_auth.state=foostate" }],
        },
      })
    );
    // Cookie should be secure and HttpOnly.
    assertIsResponse(response);
    expect(response.headers["set-cookie"][0].value).toContain("; HttpOnly");
    expect(response.headers["set-cookie"][0].value).toContain("; Secure");

    const tokenCookie = cookie.parse(response.headers["set-cookie"][0].value);
    const parsed = await jwtVerify(
      tokenCookie._auth,
      new TextEncoder().encode("foo")
    );
    expect(parsed.payload).toMatchObject({
      token: "foo",
    });
  });

  test("Responds to callback for invalid code by throwing access denied", async function () {
    const response = await proxy.handleEvent(
      makeEvent({
        uri: "/oauth/callback",
        querystring: "code=invalidcode&state=foostate",
        headers: {
          cookie: [{ key: "Cookie", value: "_auth.state=foostate" }],
        },
      })
    );
    assertIsResponse(response);
    expect(response.status).toEqual("403");
  });

  test("Response to callback for invalid state by throwing access denied", async function () {
    const response = await proxy.handleEvent(
      makeEvent({
        uri: "/oauth/callback",
        querystring: "code=letmein&state=barstate",
        headers: {
          cookie: [{ key: "Cookie", value: "_auth.state=foostate" }],
        },
      })
    );
    assertIsResponse(response);
    expect(response.status).toEqual("403");
  });
});

const dummyLogger = mock<typeof console>();
