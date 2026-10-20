// Pages does not honor Range on a static mp4, so the player cannot seek.
// This worker answers a Range on the film with 206 and passes every other request through.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/video/keeper.mp4") {
      const range = request.headers.get("Range");
      if (range) {
        return slice(request, env, range);
      }
    }
    return env.ASSETS.fetch(request);
  },
};

async function slice(request, env, range) {
  const asset = await env.ASSETS.fetch(new Request(request.url, { method: "GET" }));
  if (!asset.ok || !asset.body) {
    return asset;
  }
  const bytes = new Uint8Array(await asset.arrayBuffer());
  const size = bytes.byteLength;
  const match = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
  if (!match) {
    return assetResponse(asset, bytes);
  }
  let start = match[1] === "" ? size - Number(match[2]) : Number(match[1]);
  let end = match[2] === "" || match[1] === "" ? size - 1 : Number(match[2]);
  if (!Number.isFinite(start) || !Number.isFinite(end) || start < 0 || start >= size || end < start) {
    return new Response(null, {
      status: 416,
      headers: { "Content-Range": `bytes */${size}` },
    });
  }
  end = Math.min(end, size - 1);
  const body = bytes.subarray(start, end + 1);
  const headers = new Headers(asset.headers);
  headers.set("Content-Range", `bytes ${start}-${end}/${size}`);
  headers.set("Content-Length", String(body.byteLength));
  headers.set("Accept-Ranges", "bytes");
  return new Response(body, { status: 206, headers });
}

function assetResponse(asset, bytes) {
  const headers = new Headers(asset.headers);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Content-Length", String(bytes.byteLength));
  return new Response(bytes, { status: asset.status, headers });
}
