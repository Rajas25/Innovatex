export default function CodeBlock({ code, wrap = false, variant, caption }) {
  return (
    <div>
      {caption && <div className="code__caption">{caption}</div>}
      <pre className={`code${wrap ? ' code--wrap' : ''}${variant ? ` code--${variant}` : ''}`}>
        {code}
      </pre>
    </div>
  );
}