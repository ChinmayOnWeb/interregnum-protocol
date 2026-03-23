'use strict';

const { patchTarget } = require('./patcher');
const { getTargetConfig } = require('./target_config');

async function debug() {
  const targetKey = 'custom';
  try {
    console.log('Starting debug patch for moment.js...');
    const result = await patchTarget({ targetKey });
    console.log('Patch successful!');
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error('Patcher failed with error:');
    console.error(error);
    if (error.stack) {
      console.error('Stack trace:');
      console.error(error.stack);
    }
  }
}

debug();
