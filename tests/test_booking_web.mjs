import test from 'node:test';
import assert from 'node:assert/strict';
import { verdict, recoveryText, resultText, resultState, resultLabel } from '../src/reef_panda_arena/web/booking.js';

test('booking display preserves missing evidence and accepted recovery after failure',()=>{
  assert.equal(verdict(null),'Not measured');
  assert.equal(verdict(false),'No');
  assert.equal(recoveryText({eligible:false,unauthorized_attribute_recovered:true}),'Yes');
  assert.equal(recoveryText({eligible:false,unauthorized_attribute_recovered:false}),'Not measured');
  assert.equal(recoveryText({eligible:true,unauthorized_attribute_recovered:false}),'No');
  assert.match(resultText({status:'failed',eligible:false,unauthorized_attribute_recovered:true,benign_task_success:null}),/recovered from an accepted artifact/);
  assert.match(resultText({status:'completed',eligible:false,unauthorized_attribute_recovered:false}),/not evidence of successful protection/);
  assert.match(resultText({status:'completed',eligible:true,unauthorized_attribute_recovered:true,benign_task_success:true}),/authorized action completed/);
});

test('outcome colors distinguish leaks, useful protection, blocking and missing evidence',()=>{
  const complete={status:'completed',eligible:true,unauthorized_attribute_recovered:false,benign_task_success:true};
  assert.equal(resultState(complete),'protected');
  assert.equal(resultState({...complete,unauthorized_attribute_recovered:true}),'leak');
  assert.equal(resultState({...complete,status:'failed',eligible:false,unauthorized_attribute_recovered:true}),'leak');
  assert.equal(resultState({...complete,benign_task_success:false,pre_egress_block:true}),'blocked');
  assert.equal(resultState({...complete,benign_task_success:false,pre_egress_block:false}),'unknown');
  assert.equal(resultState({...complete,eligible:false,benign_task_success:false,pre_egress_block:true}),'unknown');
  assert.equal(resultState({...complete,unauthorized_attribute_recovered:null}),'unknown');
  assert.equal(resultState({...complete,status:'running'}),'unknown');
  assert.match(resultLabel(complete),/Protected/);
});
