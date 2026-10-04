import { render } from './render';
export function route(req: any, res: any) {
  render(req.query.html, res);
}
