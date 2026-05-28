/**
 * Newsletter signup. Renders nothing unless NEXT_PUBLIC_NEWSLETTER_URL
 * is set (point it at Buttondown / ConvertKit / Substack / your own
 * mailer). The action URL is opaque to this component, so the same
 * codebase works with any provider.
 */
import { getTranslations } from "next-intl/server";

export async function NewsletterSignup({ locale }: { locale: string }) {
  const url = process.env.NEXT_PUBLIC_NEWSLETTER_URL;
  if (!url) return null;
  const t = await getTranslations({ locale, namespace: "Newsletter" });
  return (
    <aside className="rounded-lg border border-[hsl(var(--border))] p-4 space-y-2">
      <h3 className="font-semibold text-sm">{t("title")}</h3>
      <p className="text-xs text-[hsl(var(--muted-foreground))]">{t("blurb")}</p>
      <form action={url} method="post" className="flex gap-2">
        <input
          type="email"
          name="email"
          required
          placeholder={t("placeholder")}
          className="flex-1 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--muted))] px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-red-500"
        />
        <button
          type="submit"
          className="rounded-md bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 px-3 py-1.5 text-sm font-medium"
        >
          {t("subscribe")}
        </button>
      </form>
    </aside>
  );
}
