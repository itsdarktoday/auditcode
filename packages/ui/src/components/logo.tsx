import { type ComponentProps } from "solid-js"

export const Mark = (props: { class?: string }) => {
  return (
    <svg
      data-component="logo-mark"
      classList={{ [props.class ?? ""]: !!props.class }}
      viewBox="0 0 16 20"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path data-slot="logo-logo-mark-shadow" d="M12 16H4V8H12V16Z" fill="var(--icon-weak-base)" />
      <path data-slot="logo-logo-mark-o" d="M12 4H4V16H12V4ZM16 20H0V0H16V20Z" fill="var(--icon-strong-base)" />
    </svg>
  )
}

export const Splash = (props: Pick<ComponentProps<"svg">, "ref" | "class">) => {
  return (
    <svg
      ref={props.ref}
      data-component="logo-splash"
      classList={{ [props.class ?? ""]: !!props.class }}
      viewBox="0 0 80 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path d="M60 80H20V40H60V80Z" fill="var(--icon-base)" />
      <path d="M60 20H20V80H60V20ZM80 100H0V0H80V100Z" fill="var(--icon-strong-base)" />
    </svg>
  )
}

export const Logo = (props: { class?: string }) => {
  // Pixel wordmark spelling "auditcode" on a 6px grid, cell pitch 30.
  // The six glyphs shared with the old "opencode" mark (p, e, n, c, o, d) are
  // reused verbatim and translated into place; t and s are drawn as rects in
  // the same style. "audit" uses --icon-base, "code" uses --icon-strong-base
  // to preserve the original two-tone emphasis.
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 324 42"
      fill="none"
      classList={{ [props.class ?? ""]: !!props.class }}
    >
      <g>
        {/* p — cell 0 (source cell 30, dx -30) */}
        <g transform="translate(-30,0)">
          <path d="M48 30H36V18H48V30Z" fill="var(--icon-weak-base)" />
          <path d="M36 30H48V12H36V30ZM54 36H36V42H30V6H54V36Z" fill="var(--icon-base)" />
        </g>
        {/* e — cell 30 (source cell 60, dx -30) */}
        <g transform="translate(-30,0)">
          <path d="M84 24V30H66V24H84Z" fill="var(--icon-weak-base)" />
          <path d="M84 24H66V30H84V36H60V6H84V24ZM66 18H78V12H66V18Z" fill="var(--icon-base)" />
        </g>
        {/* n — cell 60 (source cell 90, dx -30) */}
        <g transform="translate(-30,0)">
          <path d="M108 36H96V18H108V36Z" fill="var(--icon-weak-base)" />
          <path d="M108 12H96V36H90V6H108V12ZM114 36H108V12H114V36Z" fill="var(--icon-base)" />
        </g>
        {/* t — cell 90 */}
        <g transform="translate(90,0)" fill="var(--icon-base)">
          <rect x="6" y="6" width="6" height="6" />
          <rect x="0" y="12" width="18" height="6" />
          <rect x="6" y="18" width="6" height="6" />
          <rect x="6" y="24" width="6" height="6" />
          <rect x="6" y="30" width="12" height="6" />
        </g>
        {/* e — cell 120 (source cell 60, dx +60) */}
        <g transform="translate(60,0)">
          <path d="M84 24V30H66V24H84Z" fill="var(--icon-weak-base)" />
          <path d="M84 24H66V30H84V36H60V6H84V24ZM66 18H78V12H66V18Z" fill="var(--icon-base)" />
        </g>
        {/* s — cell 150 */}
        <g transform="translate(150,0)" fill="var(--icon-base)">
          <rect x="0" y="6" width="24" height="6" />
          <rect x="0" y="12" width="6" height="6" />
          <rect x="0" y="18" width="24" height="6" />
          <rect x="18" y="24" width="6" height="6" />
          <rect x="0" y="30" width="24" height="6" />
        </g>
        {/* t — cell 180 */}
        <g transform="translate(180,0)" fill="var(--icon-base)">
          <rect x="6" y="6" width="6" height="6" />
          <rect x="0" y="12" width="18" height="6" />
          <rect x="6" y="18" width="6" height="6" />
          <rect x="6" y="24" width="6" height="6" />
          <rect x="6" y="30" width="12" height="6" />
        </g>
        {/* c — cell 210 (source cell 120, dx +90) */}
        <g transform="translate(90,0)">
          <path d="M144 30H126V18H144V30Z" fill="var(--icon-weak-base)" />
          <path d="M144 12H126V30H144V36H120V6H144V12Z" fill="var(--icon-strong-base)" />
        </g>
        {/* o — cell 240 (source cell 0, dx +240) */}
        <g transform="translate(240,0)">
          <path d="M18 30H6V18H18V30Z" fill="var(--icon-weak-base)" />
          <path d="M18 12H6V30H18V12ZM24 36H0V6H24V36Z" fill="var(--icon-strong-base)" />
        </g>
        {/* d — cell 270 (source cell 180, dx +90) */}
        <g transform="translate(90,0)">
          <path d="M198 30H186V18H198V30Z" fill="var(--icon-weak-base)" />
          <path d="M198 12H186V30H198V12ZM204 36H180V6H198V0H204V36Z" fill="var(--icon-strong-base)" />
        </g>
        {/* e — cell 300 (source cell 60, dx +240) */}
        <g transform="translate(240,0)">
          <path d="M84 24V30H66V24H84Z" fill="var(--icon-weak-base)" />
          <path d="M84 24H66V30H84V36H60V6H84V24ZM66 18H78V12H66V18Z" fill="var(--icon-strong-base)" />
        </g>
      </g>
    </svg>
  )
}
