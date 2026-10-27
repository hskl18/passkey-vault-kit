import { writeFile } from 'node:fs/promises';
import { createReferenceFixture, createReferenceFixtureV2 } from '../test/reference.mjs';

for (const [name, fixture] of [['v1-fixture.json', createReferenceFixture()], ['v2-fixture.json', createReferenceFixtureV2()]]) {
  await writeFile(new URL(`../examples/${name}`, import.meta.url), `${JSON.stringify(fixture, null, 2)}\n`);
}
