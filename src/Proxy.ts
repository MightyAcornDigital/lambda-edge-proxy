import { URLSearchParams } from "url";
import cookie from "cookie";
import { CloudFrontRequestEvent, CloudFrontRequest } from "aws-lambda";
import { CloudFrontHeaders } from "aws-lambda/common/cloudfront";
import { SignJWT, jwtVerify, JWTPayload } from "jose";
import { Client, generators, TokenSet, UserinfoResponse } from "openid-client";

type ProxyOpts = {
  baseUrl?: string;
  hashKey?: string;
  authorizer?: Authorizer;
  authCookieName?: string;
  pathLogin?: string;
  pathCallback?: string;
  pathLogout?: string;
  logger?: typeof console;
};

type Authorizer = (
  token: TokenSet,
  userInfo: UserinfoResponse
) => Promise<void>;
export const PROXY_PASS = Symbol("PROXY_PASS");

class Proxy {
  private baseUrl: string | false;
  private authCookieName: string;
  private pathLogin: string;
  private pathCallback: string;
  private pathLogout: string;
  private logger: typeof console;
  private secret: Uint8Array;
  private authorize: Authorizer;

  constructor(private client: Client, opts: ProxyOpts = {}) {
    if (!opts.hashKey)
      throw new Error("opts.hashKey must be set when constructing proxy");

    this.baseUrl = opts.baseUrl || false;
    this.authCookieName = opts.authCookieName || "_auth";
    this.pathLogin = opts.pathLogin || "/auth/login";
    this.pathCallback = opts.pathCallback || "/auth/callback";
    this.pathLogout = opts.pathLogout || "/auth/logout";
    this.logger = opts.logger || console;
    this.secret = new TextEncoder().encode(opts.hashKey);
    this.authorize = opts.authorizer || (() => Promise.resolve());
  }

  async handleEvent(event: CloudFrontRequestEvent) {
    const result = await this.handleRequest(event.Records[0].cf.request);
    return result === PROXY_PASS ? event.Records[0].cf.request : result;
  }

  /**
   * Route a request to the proper method.
   *
   * @param request
   * @return {*}
   */
  private async handleRequest(request: CloudFrontRequest) {
    const currentUser = await this.getCurrentUser(request);
    if (request.uri === this.pathLogin) {
      return this.handleLogin(request, currentUser);
    }
    if (request.uri === this.pathCallback) {
      return this.handleCallback(request, currentUser);
    }
    if (request.uri === this.pathLogout) {
      return this.handleLogout(request, currentUser);
    }
    return this.handleRestricted(request, currentUser);
  }

  /**
   * Handle the user visiting the login page.
   *
   * @param request
   * @param currentUser
   * @return {*}
   */
  private handleLogin(
    request: CloudFrontRequest,
    currentUser: null | JWTPayload
  ) {
    const qs = new URLSearchParams(request.querystring);
    const next = this.filterDestination(qs.get("destination"));
    if (currentUser !== null) return this.sendTo(next, request, currentUser);

    const state = generators.state();
    const redirect_uri = `${this.getBaseUrl(request)}${
      this.pathCallback
    }?destination=${next}`;
    const authorizeURL = this.client.authorizationUrl({
      redirect_uri,
      state,
      scope: "user:email",
    });

    const response = {
      status: "302",
      statusDescription: "Login",
      body: "Login",
      headers: {
        location: [{ key: "Location", value: authorizeURL }],
        "set-cookie": [
          {
            key: "Set-Cookie",
            value: cookie.serialize(this.getAuthCookieName("state"), state, {
              httpOnly: true,
              secure: true,
              path: "/",
            }),
          },
        ],
      },
    };
    return Promise.resolve(response);
  }

  /**
   * Handle the user visiting callback page.
   *
   * @param request
   * @param currentUser
   * @return {Promise<Response>}
   */
  private async handleCallback(
    request: CloudFrontRequest,
    currentUser: null | JWTPayload
  ) {
    const qs = new URLSearchParams(request.querystring);
    const state = qs.get("state") ?? undefined;
    const code = qs.get("code") ?? undefined;
    const next = this.filterDestination(qs.get("destination"));
    const expected_state = cookie.parse(
      request.headers.cookie?.[0].value ?? ""
    )[this.getAuthCookieName("state")];

    const redirect_uri = `${this.getBaseUrl(request)}${
      this.pathCallback
    }?destination=${next}`;

    try {
      const tokenSet = await this.client.oauthCallback(
        redirect_uri,
        { code, state },
        {
          response_type: "code",
          state: expected_state,
        }
      );
      const userInfo = await this.client.userinfo(tokenSet);
      if (!userInfo) throw new Error("No user info returned");
      await this.authorize(tokenSet, userInfo);
      const token = await new SignJWT({
        tokenSet,
        userInfo,
      })
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime("12h")
        .sign(this.secret);

      return this.sendTo(next, request, currentUser, {
        "set-cookie": [
          {
            key: "Set-Cookie",
            value: cookie.serialize(this.getAuthCookieName(), token, {
              httpOnly: true,
              secure: true,
              path: "/",
            }),
          },
          {
            key: "Set-Cookie",
            value: cookie.serialize(this.getAuthCookieName("state"), "", {
              httpOnly: true,
              secure: true,
              path: "/",
              expires: new Date(0),
            }),
          },
        ],
      });
    } catch (err) {
      this.logger.error("Error handling authentication:", err);
      return Promise.resolve({
        status: "403",
        statusDescription: "Access denied",
        body: "Access Denied",
      });
    }
  }

  /**
   * Handle the user visiting the logout page.
   *
   * @param request
   * @param currentUser
   * @return {Promise<Response>}
   */
  private handleLogout(
    request: CloudFrontRequest,
    currentUser: null | JWTPayload
  ) {
    const qs = new URLSearchParams(request.querystring);
    const next = this.filterDestination(qs.get("destination"));
    return this.sendTo(next, request, currentUser, {
      "set-cookie": [
        {
          key: "Set-Cookie",
          value: cookie.serialize(this.authCookieName, "", {
            httpOnly: true,
            secure: true,
            path: "/",
            expires: new Date(0),
          }),
        },
      ],
    });
  }

  /**
   * Handle the user visiting any page that should be restricted.
   *
   * @param request
   * @param currentUser
   * @return {*}
   */
  private handleRestricted(
    request: CloudFrontRequest,
    currentUser: null | JWTPayload
  ) {
    if (currentUser !== null) {
      return Promise.resolve(PROXY_PASS);
    }
    const qs = new URLSearchParams({
      destination: `${request.uri}${
        request.querystring ? `?${request.querystring}` : ""
      }`,
    });
    return Promise.resolve({
      status: "302",
      statusDescription: "Login Required",
      headers: {
        location: [
          { key: "Location", value: `${this.pathLogin}?${qs.toString()}` },
        ],
      },
      body: "Unauthorized",
    });
  }

  /**
   * Send a user to a predefined destination, optionally specifying response headers.
   *
   * @param destination
   * @param request
   * @param currentUser
   * @param headers
   * @return {Promise<{status: string, headers: *}>}
   */
  private sendTo(
    destination: string,
    request: CloudFrontRequest,
    currentUser: null | JWTPayload,
    headers = {}
  ) {
    return Promise.resolve({
      status: "302",
      headers: Object.assign({}, headers, {
        location: [{ key: "Location", value: destination }],
      }),
    });
  }

  /**
   * Retrieves whatever data is stored about the current user.
   *
   * @param request
   * @return {*}
   */
  private async getCurrentUser(
    request: CloudFrontRequest
  ): Promise<null | JWTPayload> {
    const headers = request.headers;
    const parsedCookies = parseCookies(headers);
    const authToken = parsedCookies[this.authCookieName];
    if (authToken) {
      try {
        const result = await jwtVerify(authToken, this.secret);
        return result.payload;
      } catch (err) {
        this.logger.warn("Token validation failed: ", err);
        // No-op
      }
    }
    return null;
  }

  private getAuthCookieName(suffix?: string) {
    return [this.authCookieName, suffix].filter(Boolean).join(".");
  }

  /**
   * Check a redirect destination to see if it should be allowed.
   *
   * @param destination
   * @return {*|string}
   */
  private filterDestination(destination: string | null) {
    // @todo: Ensure destination should be allowed for a redirect.
    return destination || "/";
  }

  private getBaseUrl(request: CloudFrontRequest) {
    if (this.baseUrl) {
      return this.baseUrl;
    }
    if ("host" in request.headers) {
      return `https://${request.headers.host[0].value}`;
    }
    throw new Error("Unable to determine host.");
  }
}

export default Proxy;

function parseCookies(headers: CloudFrontHeaders) {
  const ck = headers.cookie?.[0].value ?? "";
  return cookie.parse(ck);
}
