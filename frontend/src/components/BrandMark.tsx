export function BrandMark({ size = "md" }: { size?: "md" | "lg" }) {
  return (
    <span className="inline-flex items-center gap-2">
      <svg aria-hidden="true" viewBox="0 0 32 32" className={size === "lg" ? "h-8 w-8" : "h-6 w-6"}>
        <path className="fill-accent" d="M10.2 1.5h11.6l8.7 8.7v11.6l-8.7 8.7H10.2l-8.7-8.7V10.2z" />
        <path
          className="fill-page"
          d="M7.5 10.5h3.1l1.9 7.4 2.1-7.4h2.8l2.1 7.4 1.9-7.4h3.1L21 21.5h-2.9L16 14.6l-2.1 6.9H11z"
        />
      </svg>
      <span
        className={`font-condensed font-semibold leading-none text-ink ${size === "lg" ? "text-2xl" : "text-lg"}`}
      >
        Warden X
      </span>
    </span>
  );
}
