import { setRequestLocale, getTranslations } from "next-intl/server";

import { isPro } from "@/lib/pro-bridge";
import { Link } from "@/i18n/navigation";
import { UpgradeButton } from "@/components/UpgradeButton";

export const dynamic = "force-dynamic";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  const t = await getTranslations({ locale, namespace: "Pricing" });
  return {
    title: `${t("title")} — VulnScope`,
    description: t("intro"),
  };
}

export default async function Pricing({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  setRequestLocale(locale);
  const t = await getTranslations("Pricing");
  const alreadyPro = await isPro();

  return (
    <div className="max-w-5xl mx-auto py-10 space-y-8">
      <header className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
        <p className="text-[hsl(var(--muted-foreground))] max-w-2xl">
          {t("intro")}
        </p>
      </header>

      <div className="grid md:grid-cols-3 gap-4">
        <Card
          name={t("selfhost.name")}
          price={t("selfhost.price")}
          tagline={t("selfhost.tagline")}
          features={[
            t("selfhost.f1"),
            t("selfhost.f2"),
            t("selfhost.f3"),
            t("selfhost.f4"),
            t("selfhost.f5"),
          ]}
          cta={
            <a
              href="https://github.com/Jason-chen-taiwan/vulnscope#deploy-your-own"
              className="block w-full rounded-md border border-[hsl(var(--border))] text-center py-2 text-sm hover:bg-[hsl(var(--accent))]"
            >
              {t("selfhost.cta")}
            </a>
          }
        />

        <Card
          name={t("freeHosted.name")}
          price={t("freeHosted.price")}
          tagline={t("freeHosted.tagline")}
          features={[
            t("freeHosted.f1"),
            t("freeHosted.f2"),
            t("freeHosted.f3"),
            t("freeHosted.f4"),
            t("freeHosted.f5"),
          ]}
          cta={
            <Link
              href="/sign-in"
              className="block w-full rounded-md border border-[hsl(var(--border))] text-center py-2 text-sm hover:bg-[hsl(var(--accent))]"
            >
              {t("freeHosted.cta")}
            </Link>
          }
        />

        <Card
          name={t("pro.name")}
          price={t("pro.price")}
          tagline={t("pro.tagline")}
          featured
          features={[
            t("pro.f1"),
            t("pro.f2"),
            t("pro.f3"),
            t("pro.f4"),
            t("pro.f5"),
          ]}
          cta={<UpgradeButton alreadyPro={alreadyPro} />}
        />
      </div>

      <footer className="text-sm text-[hsl(var(--muted-foreground))] space-y-2 pt-6 border-t border-[hsl(var(--border))]">
        <p>
          {t.rich("footer.refund", {
            strong: (chunks) => <strong>{chunks}</strong>,
            email: (chunks) => (
              <a className="underline" href="mailto:jason@vulnscope.dev">
                {chunks}
              </a>
            ),
          })}
        </p>
        <p>
          {t.rich("footer.polar", {
            polar: (chunks) => (
              <a
                className="underline"
                href="https://polar.sh"
                target="_blank"
                rel="noopener noreferrer"
              >
                {chunks}
              </a>
            ),
          })}
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
