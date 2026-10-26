import { useMemo } from "react";
import { encode } from "uqr";

/** Dark on white whatever the theme, with the four-module quiet zone scanners expect. */
export function QrCode({ value, label }: { value: string; label: string }) {
  const { size, path } = useMemo(() => {
    const { size, data } = encode(value, { ecc: "M", border: 4 });
    const path = data.flatMap((row, y) => row.map((dark, x) => (dark ? `M${x} ${y}h1v1h-1z` : ""))).join("");
    return { size, path };
  }, [value]);
  return (
    <svg role="img" aria-label={label} viewBox={`0 0 ${size} ${size}`} shapeRendering="crispEdges" className="size-44 shrink-0 rounded-md bg-white">
      <path d={path} className="fill-black" />
    </svg>
  );
}
