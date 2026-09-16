/*!
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as fs from 'fs';
import * as path from 'path';
import { URL } from 'url';
import mime from 'mime';
import { combineHeadersForUrl, BundleBuilder } from 'wbn';
import { IntegrityBlockSigner } from 'wbn-sign';
import { checkAndAddIwaHeaders } from './iwa-headers.js';
import { ValidIbSignPluginOptions, ValidPluginOptions } from './types.js';

// Exchange URLs are built by string-concatenating `baseURL` with a path derived
// from filesystem names or bundler chunk names. POSIX path components may
// legally contain ':', so a crafted directory tree such as `https:/evil/x.js`
// can turn the concatenated result into an absolute URL for a foreign origin.
// Reject any exchange URL that does not stay on `baseURL`'s origin (or, when
// `baseURL` is empty or relative, any exchange URL that parses as absolute at all).
export function assertExchangeUrlOrigin(exchangeUrl: string, baseURL: string) {
  let parsed: URL;
  try {
    parsed = new URL(exchangeUrl);
  } catch {
    return; // Not an absolute URL; nothing to check.
  }

  let baseParsed: URL;
  try {
    baseParsed = new URL(baseURL);
  } catch {
    // baseURL is not an absolute URL, so exchangeUrl should not be absolute either.
    throw new Error(
      `Refusing to add exchange with unexpected origin: ${exchangeUrl}`
    );
  }

  if (
    parsed.protocol !== baseParsed.protocol ||
    parsed.host !== baseParsed.host ||
    parsed.port !== baseParsed.port
  ) {
    throw new Error(
      `Refusing to add exchange with unexpected origin: ${exchangeUrl}`
    );
  }
}

// If the file name is 'index.html', create an entry for both baseURL/dir/ and
// baseURL/dir/index.html which redirects to the aforementioned. Otherwise just
// for the asset itself. This matches the behavior of gen-bundle.
export function addAsset(
  builder: BundleBuilder,
  baseURL: string,
  relativeAssetPath: string, // Asset's path relative to app's base dir. E.g. sub-dir/helloworld.js
  assetContentBuffer: Uint8Array | string,
  pluginOptions: ValidPluginOptions
) {
  const parsedAssetPath = path.parse(relativeAssetPath);
  const isIndexHtmlFile = parsedAssetPath.base === 'index.html';

  // For object type, the IWA headers have already been check in constructor.
  const shouldCheckIwaHeaders =
    typeof pluginOptions.headerOverride === 'function' &&
    'integrityBlockSign' in pluginOptions &&
    pluginOptions.integrityBlockSign.isIwa;

  if (isIndexHtmlFile) {
    const combinedIndexHeaders = combineHeadersForUrl(
      { Location: './' },
      pluginOptions.headerOverride,
      baseURL + relativeAssetPath
    );
    if (shouldCheckIwaHeaders) checkAndAddIwaHeaders(combinedIndexHeaders);

    assertExchangeUrlOrigin(baseURL + relativeAssetPath, baseURL);
    builder.addExchange(
      baseURL + relativeAssetPath,
      301,
      combinedIndexHeaders,
      '' // Empty content.
    );
  }

  const baseURLWithAssetPath =
    baseURL + (isIndexHtmlFile ? parsedAssetPath.dir : relativeAssetPath);
  const combinedHeaders = combineHeadersForUrl(
    {
      'Content-Type':
        mime.getType(relativeAssetPath) || 'application/octet-stream',
    },
    pluginOptions.headerOverride,
    baseURLWithAssetPath
  );
  if (shouldCheckIwaHeaders) checkAndAddIwaHeaders(combinedHeaders);

  assertExchangeUrlOrigin(baseURLWithAssetPath, baseURL);
  builder.addExchange(
    baseURLWithAssetPath,
    200,
    combinedHeaders,
    assetContentBuffer
  );
}

export function addFilesRecursively(
  builder: BundleBuilder,
  baseURL: string,
  dir: string,
  pluginOptions: ValidPluginOptions,
  recPath = ''
) {
  if (recPath === '' && fs.lstatSync(dir).isSymbolicLink()) {
    throw new Error(
      `Refusing to bundle symbolic link at ${dir}. ` +
        `Replace it with a regular file or directory.`
    );
  }

  const files = fs.readdirSync(dir);
  files.sort(); // Sort entries for reproducibility.

  for (const fileName of files) {
    const filePath = path.join(dir, fileName);

    const stat = fs.lstatSync(filePath);
    if (stat.isSymbolicLink()) {
      // Refuse to follow symlinks so that files outside the static directory
      // (credentials, SSH keys, etc.) cannot be pulled into the bundle.
      throw new Error(
        `Refusing to bundle symbolic link at ${filePath}. ` +
          `Replace it with a regular file or directory.`
      );
    }
    if (stat.isDirectory()) {
      addFilesRecursively(
        builder,
        baseURL,
        filePath,
        pluginOptions,
        recPath + fileName + '/'
      );
    } else {
      const fileContent = fs.readFileSync(filePath);
      // `fileName` contains the directory as this is done recursively for every
      // directory so it gets added to the baseURL.
      addAsset(
        builder,
        baseURL,
        recPath + fileName,
        fileContent,
        pluginOptions
      );
    }
  }
}

export async function getSignedWebBundle(
  webBundle: Uint8Array,
  opts: ValidIbSignPluginOptions,
  infoLogger: (str: string) => void
): Promise<Uint8Array> {
  const { signedWebBundle } = await new IntegrityBlockSigner(
    /*is_v2=*/ true,
    webBundle,
    opts.integrityBlockSign.webBundleId,
    opts.integrityBlockSign.strategies
  ).sign();

  infoLogger(opts.integrityBlockSign.webBundleId);
  return signedWebBundle;
}
