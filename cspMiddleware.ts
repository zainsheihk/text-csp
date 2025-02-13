import { NextFetchEvent, NextRequest, NextResponse } from "next/server";
import { CustomMiddleware } from "./middleware";

export function cspMiddleware(middleware: CustomMiddleware) {
  return (
    request: NextRequest,
    event: NextFetchEvent,
    response: NextResponse
  ) => {
    const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
    const cloudfrontDomain = "https://d2oqzssnygpru4.cloudfront.net";
    const stagingUrl = "https://staging.cciglobal.com";

    // Combined Content Security Policy
    const cspHeader = `
      default-src 'self';
      script-src 'self' 'unsafe-inline' 'nonce-${nonce}' ${stagingUrl}  https://www.google.com https://www.gstatic.com;
      script-src-elem 'self' 'unsafe-inline' ${stagingUrl} https://www.google.com https://www.gstatic.com;
      style-src 'self' 'unsafe-inline' ${stagingUrl} https://fonts.googleapis.com ;
      img-src 'self' blob: data: ${cloudfrontDomain} ${stagingUrl} https://www.gstatic.com https://www.youtube.com;
      font-src 'self' https://fonts.gstatic.com data:;
      object-src 'none';
      base-uri 'self';
      form-action 'self';
      frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com https://www.google.com;
      media-src 'self' data: blob: ${cloudfrontDomain} https://*.cloudfront.net;
      connect-src 'self' data: blob: ${cloudfrontDomain} https://*.cloudfront.net  ${stagingUrl} https://cciglobal.s3.amazonaws.com;
      worker-src 'self' blob:;
      frame-ancestors 'none';
      upgrade-insecure-requests;
    `;

    // Clean the CSP header
    const contentSecurityPolicyHeaderValue = cspHeader
      .replace(/\s{2,}/g, " ")
      .trim();

    // Create the response

    // Set security headers
    response.headers.set("x-nonce", nonce);
    response.headers.set(
      "Content-Security-Policy",
      contentSecurityPolicyHeaderValue
    );
    response.headers.set(
      "Access-Control-Allow-Origin",
      "https://staging.cciglobal.com https://www.google.com https://www.gstatic.com https://www.youtube.com https://www.youtube-nocookie.com https://d2oqzssnygpru4.cloudfront.net https://cciglobal.s3.amazonaws.com"
    );
    response.headers.set("X-Content-Type-Options", "nosniff");
    response.headers.set("X-Frame-Options", "DENY");
    response.headers.set("X-XSS-Protection", "1; mode=block");
    response.headers.set("Server", ""); // Hide server details
    response.headers.set("X-Powered-By", ""); // Hide framework info
    response.headers.set(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, DELETE, OPTIONS"
    );
    response.headers.set("Access-Control-Allow-Origin", stagingUrl);
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    response.headers.set(
      "Permissions-Policy",
      "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()"
    );

    response.headers.set(
      "Cache-Control",
      "private, no-cache, no-store, max-age=0, must-revalidate"
    );

    return middleware(request, event, response);
  };
}
