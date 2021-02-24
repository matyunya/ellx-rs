import { join } from 'path';
import fs, { Stats } from 'fs';
import { FSRequest, FSResponse } from '../index';

const { stat, readFile, readdir, mkdir, writeFile, rmdir, unlink, rename, copyFile } = fs.promises;

async function sendFile(res: FSResponse, file: string, stats: Stats): Promise<void> {
  const headers = {
    'Content-Length': stats.size,
    'Content-Type': 'text/plain' //mime.getType(file)
  };

  res.writeHead(200, headers);
  res.end(await readFile(file, { encoding: 'utf8' }));
}

async function sendDirectory(res: FSResponse, filePath: string): Promise<void> {
  const items = await readdir(filePath, { withFileTypes: true });

  res.sendJson(items
    .filter(item => !item.name.startsWith('.') && (item.isDirectory() || item.isFile()))
    .map(item => item.name + (item.isDirectory() ? '/' : ''))
  );
}

async function copyDirectory(filePath: string, newPath: string): Promise<any> {
  await mkdir(newPath);
  const items = await readdir(filePath, { withFileTypes: true });

  return Promise.all(items
    .map(item => (item.isDirectory() ? copyDirectory : copyFile)(
      join(filePath, item.name),
      join(newPath, item.name)
    )));
}

async function makeOne(filePath: string, contents = '', secondTry = false): Promise<any> {
  try {
    // TODO: set proper access rights mode
    if (filePath.endsWith('/')) await mkdir(filePath);
    else await writeFile(filePath, contents, 'utf8');
  }
  catch (e) {
    if (e.code === 'ENOENT') {
      if (secondTry) throw e;

      await makeOne(join(filePath, '../'));
      return makeOne(filePath, contents, true);
    }
    if (e.code !== 'EEXIST') throw e;
  }
}

function makeResources(filePath: string, files: [string, string][]) {
  const filesMap = new Map(files
    .filter(Array.isArray)
    .map(([path, contents]) => [join(filePath, decodeURI(path)), contents && String(contents)] as [string, string])
    .filter(([path]) => path.startsWith(filePath))
  );

  return Promise.all([...filesMap].map(pair => makeOne(...pair)));
}

const serve = (root: string) => async (req: FSRequest, res: FSResponse) => {
  const filePath = join(root, decodeURI(req.path));

  console.log(req.method + ' ' + filePath);
  if (Object.keys(req.body).length) console.log(req.body);

  if (!filePath.startsWith(root)) {
    return res.error('Unauthorized', 401);
  }

  try {
    const stats = await stat(filePath);

    if (req.method === 'GET') {
      if (stats.isDirectory()) return await sendDirectory(res, filePath);
      else if (stats.isFile()) return await sendFile(res, filePath, stats);
      else return res.error('Unsupported resource type', 400);
    }
    else if (req.method === 'PUT') {
      const { files } = req.body;
      if (!stats.isDirectory()) return res.error(`${filePath} is not a directory`, 400);
      if (!Array.isArray(files)) return res.error('Bad files argument', 400);

      await makeResources(filePath, files);
    }
    else if (req.method === 'DELETE') {
      if (stats.isDirectory()) await rmdir(filePath, { recursive: true });
      else await unlink(filePath);
    }
    else if (req.method === 'POST') {
      const { action, destination } = req.body;

      const newPath = join(root, decodeURI(destination));
      if (!newPath.startsWith(root)) return res.error('Unauthorized', 401);

      if (action === 'move') {
        await rename(filePath, newPath);
      }
      else if (action === 'copy') {
        if (stats.isDirectory()) await copyDirectory(filePath, newPath);
        else await copyFile(filePath, newPath);
      }
      else return res.error('Unrecognized action: ' + action, 400);
    }
    else return res.error('Unsupported method', 400);

    res.end('success');
  }
  catch (e) {
    if (e.code === 'ENOENT') res.error('Not found', 404);
    else res.error(e.code, 400);
  }
}

export default serve;
