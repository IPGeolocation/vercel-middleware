// Drop in proxy for Next.js 16.
// Copy this file to proxy.ts at your project root. Next.js 16 renamed
// middleware.ts to proxy.ts and expects an exported function named proxy.

import { proxy } from 'ipgeolocation-vercel-middleware/middleware';

export { proxy };

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|_next/data|favicon.ico|robots.txt|sitemap.xml|.*\\.(?:css|js|mjs|map|json|txt|xml|ico|png|jpg|jpeg|gif|webp|avif|svg|woff|woff2|ttf|otf|eot|mp4|webm|mp3|pdf|zip)$).*)'
  ]
};
