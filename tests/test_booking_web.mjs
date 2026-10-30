import test from 'node:test';
import assert from 'node:assert/strict';
import { verdict, recoveryText, resultText } from '../src/reef_panda_arena/web/booking.js';

test('booking display preserves missing evidence and accepted recovery after failure',()=>{
  assert.equal(verdict(null),'Not measured');
  assert.equal(verdict(false),'No');
  assert.equal(recoveryText({eligible:false,unauthorized_attribute_recovered:true}),'Yes');
  assert.equal(recoveryText({eligible:false,unauthorized_attribute_recovered:false}),'Not measured');
  assert.equal(recoveryText({eligible:true,unauthorized_attribute_recovered:false}),'No');
  assert.match(resultText({status:'failed',eligible:false,unauthorized_attribute_recovered:true,benign_task_success:null}),/recovered from an accepted artifact/);
  assert.match(resultText({status:'completed',eligible:false,unauthorized_attribute_recovered:false}),/not evidence of successful protection/);
  assert.match(resultText({status:'completed',eligible:true,unauthorized_attribute_recovered:true,benign_task_success:true}),/booking succeeded/);
});
