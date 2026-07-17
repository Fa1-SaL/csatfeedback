import crypto from "node:crypto";

const page = (msg) =>
    new Response(
        `<!doctype html><html><body style="font-family:sans-serif;text-align:center;padding:60px 20px"><h2>${msg}</h2></body></html>`,
        { headers: { "Content-Type": "text/html" } }
    );

export default async (req) => {
    const { searchParams } = new URL(req.url);
    const id = searchParams.get("id");
    const v = searchParams.get("v");
    const ts = searchParams.get("ts");
    const sig = searchParams.get("sig");

    if (!id || !v || !ts || !sig) return page("Link looks incomplete.");

    const expected = crypto.createHmac("sha256", process.env.CSAT_SECRET)
        .update(`${id}.${v}.${ts}`).digest("hex");

    if (sig !== expected) return page("Link looks invalid.");

    const suspect = (Date.now() - Number(ts)) < 8000;

    try {
        await fetch(process.env.N8N_CSAT_WEBHOOK, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSAT-Auth": process.env.CSAT_SECRET,
            },
            body: JSON.stringify({ id, vote: v, suspect }),
        });
    } catch (e) {
        return page("Something went wrong, but thanks for trying!");
    }

    return page(v === "yes" ? "Thanks for the feedback!" : "Thanks for the feedback!");
};

export const config = { path: "/csat" };
