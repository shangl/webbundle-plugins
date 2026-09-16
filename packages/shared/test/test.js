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

import test from 'ava';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BundleBuilder } from 'wbn';
import { getValidatedOptionsWithDefaults } from '../lib/types.js';
import { addFilesRecursively } from '../lib/utils.js';
import * as wbnSign from 'wbn-sign';

const TEST_ED25519_PRIVATE_KEY = wbnSign.parsePemKey(
  '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIB8nP5PpWU7HiILHSfh5PYzb5GAcIfHZ+bw6tcd/LZXh\n-----END PRIVATE KEY-----'
);
const TEST_IWA_BASE_URL =
  'isolated-app://4tkrnsmftl4ggvvdkfth3piainqragus2qbhf7rlz2a3wo3rh4wqaaic/';

test('headerOverride - IWA with bad headers', async (t) => {
  const badHeadersTestCase = [
    { 'cross-origin-embedder-policy': 'unsafe-none' },
    { 'cross-origin-opener-policy': 'unsafe-none' },
    { 'cross-origin-resource-policy': 'cross-origin' },
  ];

  for (const badHeaders of badHeadersTestCase) {
    for (const isIwaTestCase of [undefined, true]) {
      await t.throwsAsync(
        async () => {
          await getValidatedOptionsWithDefaults({
            baseURL: TEST_IWA_BASE_URL,
            output: 'example.swbn',
            integrityBlockSign: {
              key: TEST_ED25519_PRIVATE_KEY,
              isIwa: isIwaTestCase,
            },
            headerOverride: badHeaders,
          });
        },
        { instanceOf: Error }
      );
    }
  }
});

test('addFilesRecursively - refuses symbolic link to file', (t) => {
  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'wbn-test-symlink-file-')
  );
  try {
    const targetFile = path.join(tmpDir, 'target.txt');
    fs.writeFileSync(targetFile, 'sensitive data');
    const symlinkFile = path.join(tmpDir, 'symlink.txt');
    fs.symlinkSync(targetFile, symlinkFile);

    const builder = new BundleBuilder();
    const error = t.throws(
      () => {
        addFilesRecursively(builder, 'https://example.com/', tmpDir, {
          baseURL: 'https://example.com/',
          output: 'out.wbn',
        });
      },
      { instanceOf: Error }
    );
    t.is(
      error.message,
      `Refusing to bundle symbolic link at ${symlinkFile}. Replace it with a regular file or directory.`
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('addFilesRecursively - refuses symbolic link to directory', (t) => {
  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'wbn-test-symlink-dir-')
  );
  try {
    const targetDir = path.join(tmpDir, 'target-dir');
    fs.mkdirSync(targetDir);
    fs.writeFileSync(path.join(targetDir, 'inner.txt'), 'sensitive data');
    const symlinkDir = path.join(tmpDir, 'symlink-dir');
    fs.symlinkSync(targetDir, symlinkDir);

    const builder = new BundleBuilder();
    const error = t.throws(
      () => {
        addFilesRecursively(builder, 'https://example.com/', tmpDir, {
          baseURL: 'https://example.com/',
          output: 'out.wbn',
        });
      },
      { instanceOf: Error }
    );
    t.is(
      error.message,
      `Refusing to bundle symbolic link at ${symlinkDir}. Replace it with a regular file or directory.`
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('addFilesRecursively - refuses root directory being a symbolic link', (t) => {
  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'wbn-test-root-symlink-')
  );
  try {
    const targetDir = path.join(tmpDir, 'target-dir');
    fs.mkdirSync(targetDir);
    fs.writeFileSync(path.join(targetDir, 'inner.txt'), 'some data');
    const symlinkDir = path.join(tmpDir, 'symlink-root');
    fs.symlinkSync(targetDir, symlinkDir);

    const builder = new BundleBuilder();
    const error = t.throws(
      () => {
        addFilesRecursively(builder, 'https://example.com/', symlinkDir, {
          baseURL: 'https://example.com/',
          output: 'out.wbn',
        });
      },
      { instanceOf: Error }
    );
    t.is(
      error.message,
      `Refusing to bundle symbolic link at ${symlinkDir}. Replace it with a regular file or directory.`
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
