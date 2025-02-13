import { NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const cloudfrontDomain = "https://d2oqzssnygpru4.cloudfront.net";
  const stagingUrl = "https://text-csp.vercel.app";
  const cspHeader = `
      default-src 'self';
      script-src 'self'  'nonce-${nonce}' ${stagingUrl}  https://www.google.com https://www.gstatic.com;
      script-src-elem 'self'  ${stagingUrl} https://www.google.com https://www.gstatic.com;
      style-src 'self'  ${stagingUrl} https://fonts.googleapis.com ;
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
  // Replace newline characters and spaces
  const contentSecurityPolicyHeaderValue = cspHeader
    .replace(/\s{2,}/g, " ")
    .trim();

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);

  requestHeaders.set(
    "Content-Security-Policy",
    contentSecurityPolicyHeaderValue
  );

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });
  response.headers.set(
    "Content-Security-Policy",
    contentSecurityPolicyHeaderValue
  );

  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
