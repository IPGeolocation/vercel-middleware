// Running IPGeolocation.io alongside your own middleware logic.
//
// evaluateIpGeolocation makes the decision without sending a response, so you
// can add your own rules and still forward the geo headers to the application.

import { NextResponse, type NextRequest } from 'next/server';
import { evaluateIpGeolocation } from 'ipgeolocation-vercel-middleware/middleware';

export async function middleware(request: NextRequest) {
  const geo = await evaluateIpGeolocation(request);

  // A block or a country redirect. Return it as is.
  if (geo.response) return geo.response;

  // Your own rules, with the geo data already available.
  if (geo.country === 'DE' && request.nextUrl.pathname === '/') {
    return NextResponse.redirect(new URL('/de', request.url));
  }

  // Forward the request with the geo headers attached. Skipping this line is
  // what drops the x-ipgeo-* headers.
  return NextResponse.next({ request: { headers: geo.requestHeaders } });
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
};
