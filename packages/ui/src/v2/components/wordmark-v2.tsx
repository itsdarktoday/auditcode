import { createUniqueId, type ComponentProps } from "solid-js"

export function WordmarkV2(props: Pick<ComponentProps<"svg">, "class">) {
  const filter = createUniqueId()
  const mask = createUniqueId()
  const maskGradient = createUniqueId()

  // Pixel wordmark spelling "auditcode". The six glyphs shared with the old
  // "opencode" mark (p, e, n, c, o, d) are reused verbatim and translated into
  // place; t and s are drawn as rects in the same 18.46px-grid style.
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 996.923 129.001"
      fill="none"
      preserveAspectRatio="none"
      classList={{ [props.class ?? ""]: !!props.class }}
    >
      <g opacity="0.16" filter={`url(#${filter})`} mask={`url(#${mask})`}>
        {/* p — cell 0 */}
        <path
          opacity="0.7"
          transform="translate(-92.313,0)"
          d="M110.774 92.144H147.697V36.8583H110.774V92.144ZM166.159 110.573H110.774V129.001H92.3125V18.4297H166.159V110.573Z"
          fill="currentColor"
        />
        {/* e — cell 1 */}
        <path
          opacity="0.7"
          transform="translate(-92.309,0)"
          d="M258.463 73.7154H203.079V92.144H258.463V110.573H184.617V18.4297H258.463V73.7154ZM203.079 55.2868H240.002V36.8583H203.079V55.2868Z"
          fill="currentColor"
        />
        {/* n — cell 2 */}
        <path
          opacity="0.7"
          transform="translate(-92.307,0)"
          d="M332.306 36.8583H295.383V110.573H276.922V18.4297H332.306V36.8583ZM350.768 110.573H332.306V36.8583H350.768V110.573Z"
          fill="currentColor"
        />
        {/* t — cell 3 */}
        <g transform="translate(276.923,0)" fill="currentColor">
          <rect opacity="0.7" x="18.4615" y="18.4297" width="18.4615" height="18.4287" />
          <rect opacity="0.7" x="0" y="36.8584" width="55.3846" height="18.4287" />
          <rect opacity="0.7" x="18.4615" y="55.2871" width="18.4615" height="18.4287" />
          <rect opacity="0.7" x="18.4615" y="73.7158" width="18.4615" height="18.4287" />
          <rect opacity="0.7" x="18.4615" y="92.1445" width="36.9231" height="18.4287" />
        </g>
        {/* e — cell 4 */}
        <path
          opacity="0.7"
          transform="translate(184.614,0)"
          d="M258.463 73.7154H203.079V92.144H258.463V110.573H184.617V18.4297H258.463V73.7154ZM203.079 55.2868H240.002V36.8583H203.079V55.2868Z"
          fill="currentColor"
        />
        {/* s — cell 5 */}
        <g transform="translate(461.538,0)" fill="currentColor">
          <rect opacity="0.7" x="0" y="18.4297" width="73.8462" height="18.4287" />
          <rect opacity="0.7" x="0" y="36.8584" width="18.4615" height="18.4287" />
          <rect opacity="0.7" x="0" y="55.2871" width="73.8462" height="18.4287" />
          <rect opacity="0.7" x="55.3846" y="73.7158" width="18.4615" height="18.4287" />
          <rect opacity="0.7" x="0" y="92.1445" width="73.8462" height="18.4287" />
        </g>
        {/* t — cell 6 */}
        <g transform="translate(553.846,0)" fill="currentColor">
          <rect opacity="0.7" x="18.4615" y="18.4297" width="18.4615" height="18.4287" />
          <rect opacity="0.7" x="0" y="36.8584" width="55.3846" height="18.4287" />
          <rect opacity="0.7" x="18.4615" y="55.2871" width="18.4615" height="18.4287" />
          <rect opacity="0.7" x="18.4615" y="73.7158" width="18.4615" height="18.4287" />
          <rect opacity="0.7" x="18.4615" y="92.1445" width="36.9231" height="18.4287" />
        </g>
        {/* c — cell 7 */}
        <path
          opacity="0.7"
          transform="translate(276.920,0)"
          d="M443.081 36.8583H387.696V92.144H443.081V110.573H369.234V18.4297H443.081V36.8583Z"
          fill="currentColor"
        />
        {/* o — cell 8 */}
        <path
          opacity="0.7"
          transform="translate(738.462,0)"
          d="M55.3846 36.8583H18.4615V92.144H55.3846V36.8583ZM73.8462 110.573H0V18.4297H73.8462V110.573Z"
          fill="currentColor"
        />
        {/* d — cell 9 */}
        <path
          opacity="0.7"
          transform="translate(276.925,0)"
          d="M609.228 36.8571H572.305V92.1429H609.228V36.8571ZM627.69 110.571H553.844V18.4286H609.228V0H627.69V110.571Z"
          fill="currentColor"
        />
        {/* e — cell 10 */}
        <path
          opacity="0.7"
          transform="translate(738.460,0)"
          d="M258.463 73.7154H203.079V92.144H258.463V110.573H184.617V18.4297H258.463V73.7154ZM203.079 55.2868H240.002V36.8583H203.079V55.2868Z"
          fill="currentColor"
        />
      </g>
      <defs>
        <mask id={mask} maskUnits="userSpaceOnUse" x="0" y="0" width="997" height="129">
          <rect width="997" height="129" fill={`url(#${maskGradient})`} />
        </mask>
        <linearGradient id={maskGradient} x1="498.462" y1="0" x2="498.462" y2="112" gradientUnits="userSpaceOnUse">
          <stop stop-color="white" stop-opacity="0.7" />
          <stop offset="1" stop-color="white" stop-opacity="0" />
        </linearGradient>
        <filter
          id={filter}
          x="0"
          y="0"
          width="996.923"
          height="130.001"
          filterUnits="userSpaceOnUse"
          color-interpolation-filters="sRGB"
        >
          <feFlood flood-opacity="0" result="BackgroundImageFix" />
          <feBlend mode="normal" in="SourceGraphic" in2="BackgroundImageFix" result="shape" />
          <feColorMatrix
            in="SourceAlpha"
            type="matrix"
            values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0"
            result="hardAlpha"
          />
          <feOffset dy="1" />
          <feGaussianBlur stdDeviation="1" />
          <feComposite in2="hardAlpha" operator="arithmetic" k2="-1" k3="1" />
          <feColorMatrix type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0" />
          <feBlend mode="normal" in2="shape" result="effect1_innerShadow_4938_16028" />
        </filter>
      </defs>
    </svg>
  )
}
