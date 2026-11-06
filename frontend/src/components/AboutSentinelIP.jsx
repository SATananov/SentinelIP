export default function AboutSentinelIP() {
  return <div className="about-panel panel">
    <p className="panel-kicker">Security Operations Workspace</p>
    <p className="about-lead">A security monitoring workspace for reviewing network activity, detections, sensor operations, perimeter evidence, and incident reviews.</p>
    <div className="about-grid">
      <section><h4>Architecture</h4><p>The frontend defaults to a local API endpoint and can be configured for the API endpoint chosen by the deployment. This supports a local-first operating model; actual locality depends on the operator’s deployment and configuration.</p></section>
      <section><h4>Supported workspace capabilities</h4><ul><li>Event, alert, and severity summaries with filters and CSV, JSON, and PDF exports.</li><li>Authorized network scope and discovery workflows.</li><li>Remote sensor fleet, assigned-scope task operations, and history.</li><li>Threat detections, correlations, incident reviews, perimeter activity, and external exposure views.</li><li>Manual retention preview and explicitly confirmed cleanup.</li></ul></section>
      <section><h4>Operator responsibility</h4><p>Use SentinelIP only with appropriate authorization. The operator remains responsible for authorized use, target scope, and appropriate configuration.</p></section>
    </div>
    <section className="about-attribution" aria-label="Product attribution">
      <p className="panel-kicker">Product attribution</p>
      <strong>Tanashi Studio™</strong>
      <span>© 2026 Tanashi Studio. All rights reserved.</span>
    </section>
  </div>
}
