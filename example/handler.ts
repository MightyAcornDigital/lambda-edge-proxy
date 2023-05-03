import {CloudFrontRequestEvent} from 'aws-lambda';
import {Issuer} from "openid-client";
import {Proxy} from "@mightyacorndigital/lambda-edge-proxy";

export function onViewerRequest(event: CloudFrontRequestEvent) {
    const issuer = new Issuer({
        issuer: 'github.com',
        authorization_endpoint: 'https://github.com/login/oauth/authorize',
        token_endpoint: 'https://github.com/login/oauth/access_token',
        token_endpoint_auth_signing_alg_values_supported: ['RS256'],
        userinfo_endpoint: 'https://api.github.com/user',
    });
    const client = new issuer.Client({
        // In lambda@edge, you can't actually use environment variables, so replace these
        // with explicit values. This is here for local testing purposes.
        client_id: process.env.GITHUB_CLIENT_ID!,
        client_secret: process.env.GITHUB_CLIENT_SECRET!,
        response_types: ['code'],
    });
    const handler = new Proxy(client, {
        // Use a secure value for the hashKey. Ex: https://generate-secret.vercel.app/32
        hashKey: 'test',
        // This will be your publicly accessible domain.
        baseUrl: 'http://localhost:8081',
        scopes: ['user:email'],
        async authorizer(token, userInfo) {
            // This is where you would implement your own authorization logic.
            // Use the token and userInfo to determine if the user is authorized, and throw an
            // error if they are not.
            // throw new Error('Not authorized');
        }
    });
    return handler.handleEvent(event);
}