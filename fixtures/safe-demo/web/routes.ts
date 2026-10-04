export function route(req: any, res: any) {
  res.send(escapeHtml(req.query.html));
}
