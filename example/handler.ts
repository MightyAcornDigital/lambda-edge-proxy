import {CloudFrontRequestEvent} from 'aws-lambda';
import {Proxy} from "@mightyacorndigital/lambda-edge-proxy";
import {App} from "@octokit/app";

export function onViewerRequest(event: CloudFrontRequestEvent) {
    const app = new App({
        appId: process.env.GITHUB_APP_ID,
        privateKey: process.env.GITHUB_PRIVATE_KEY,
        oauth: {
            clientId: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
        },
    });
    const handler = new Proxy(app.oauth, {
        // Use a secure value for the hashKey. Ex: https://generate-secret.vercel.app/32
        hashKey: process.env.HASH_KEY,
        // This will be your publicly accessible domain.
        baseUrl: 'http://localhost:8080',
        scopes: ['user:email'],
        async authorizer(token: string) {
            // This is where you implement authorization logic, using the token to
            // check whether the user meets your criteria for access. Throw an error
            // to prevent access.
        }
    });
    return handler.handleEvent(event);
}