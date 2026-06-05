import { setRequestLocale } from "next-intl/server";

import { isPro } from "@/lib/pro-bridge";
import { Link } from "@/i18n/navigation";
import { UpgradeButton } from "@/components/UpgradeButton";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Pricing — VulnScope",
  description:
    "Self-host VulnScope free forever (MIT) or get the hosted Pro tier with watchlists and daily CVE email alerts for $9/month.",
};

export default async function Pricing({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  setRequestLocale(locale);
  const alreadyPro = await isPro();

  return (
    <div className="max-w-5xl mx-auto py-10 space-y-8">
      <header className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">Pricing</h1>
        <p className="text-[hsl(var(--muted-foreground))] max-w-2xl">
          VulnScope is MIT open source — clone, self-host, hack on it forever.
          The hosted Pro tier adds the things that take a server: watchlists
          and daily email alerts.
        </p>
      </header>

      <div className="grid md:grid-cols-3 gap-4">
        <Card
          name="Self-host"
          price="Free"
          tagline="Forever, MIT, no strings."
          features={[
            "Full web UI + ingest pipeline",
            "14 ecosystems (npm, PyPI, Debian, …)",
            "KEV + EPSS overlays",
            "vulnscope CLI scanner",
            "Self-hosted on your own box",
          ]}
          cta={
            <a
              href="https://github.com/Jason-chen-taiwan/vulnscope#deploy-your-own"
              className="block w-full rounded-md border border-[hsl(var(--border))] text-center py-2 text-sm hover:bg-[hsl(var(--accent))]"
            >
              Self-host docs →
            </a>
          }
        />

        <Card
          name="Free hosted"
          price="$0"
          tagline="Use our box, no signup, no ads."
          features={[
            "Web UI on vulnscope.dev",
            "Watch up to 3 packages (sign-in required)",
            "Pin a specific version, see CVEs that affect it",
            "CLI hits our public API (rate-limited)",
            "RSS feeds",
          ]}
          cta={
            <Link
              href="/sign-in"
              className="block w-full rounded-md border border-[hsl(var(--border))] text-center py-2 text-sm hover:bg-[hsl(var(--accent))]"
            >
              Sign in to start →
            </Link>
          }
        />

        <Card
          name="Pro"
          price="$9/mo"
          tagline="Stop checking. We email you."
          featured
          features={[
            "Watch up to 50 packages (vs 3 on free)",
            "Daily email digest of new CVEs",
            "KEV + EPSS rising alerts",
            "10× higher CLI API limit",
            "30-day money-back, no questions",
          ]}
          cta={<UpgradeButton alreadyPro={alreadyPro} />}
        />
      </div>

      <footer className="text-sm text-[hsl(var(--muted-foreground))] space-y-2 pt-6 border-t border-[hsl(var(--border))]">
        <p>
          <strong>30-day money-back guarantee.</strong> Don&apos;t like it?
          Email{" "}
          <a className="underline" href="mailto:jason@vulnscope.dev">
            jason@vulnscope.dev
          </a>
          {" "}and I&apos;ll refund every cent. No forms, no questions.
        </p>
        <p>
          Payments processed by{" "}
          <a
            className="underline"
            href="https://polar.sh"
            target="_blank"
            rel="noopener noreferrer"
          >
            Polar
          </a>{" "}
          (Merchant of Record). Polar handles sales tax / VAT for your
          jurisdiction; the receipt comes from Polar, not me.
        </p>
      </footer>
    </div>
  );
}

function Card({
  name,
  price,
  tagline,
  features,
  cta,
  featured = false,
}: {
  name: string;
  price: string;
  tagline: string;
  features: string[];
  cta: React.ReactNode;
  featured?: boolean;
}) {
  return (
    <div
      className={`rounded-lg border p-5 flex flex-col gap-4 ${
        featured
          ? "border-[hsl(var(--primary))] bg-[hsl(var(--primary)/0.05)]"
          : "border-[hsl(var(--border))]"
      }`}
    >
      <div className="space-y-1">
        <div className="text-sm font-semibold">{name}</div>
        <div className="text-3xl font-bold">{price}</div>
        <div className="text-sm text-[hsl(var(--muted-foreground))]">
          {tagline}
        </div>
      </div>
      <ul className="space-y-1.5 text-sm flex-1">
        {features.map((f) => (
          <li key={f} className="flex gap-2">
            <span className="text-[hsl(var(--primary))]">✓</span>
            <span>{f}</span>
          </li>
        ))}
      </ul>
      <div>{cta}</div>
    </div>
  );
}
