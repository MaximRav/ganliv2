const express = require('express');
const _ = require('lodash');
const co = require('co');
const validatez = require('validatez');
const debug = require('debug');

const _debug = false;

const filter = (_rconfg, fconfig = {}) => {
  const filters = _rconfg.filters || [];
  return filters.map((sel) => {
    const fn = _.get(fconfig, sel);
    return (req, res, next) =>
      co(fn(req, res)).then(next.bind(null, null)).catch(next);
  });
};

const getMethod = (parent, _rconfg) => {
  const method = _rconfg.method || 'GET';
  switch (method.toUpperCase()) {
    case 'POST':
      return parent.post.bind(parent);
    case 'PUT':
      return parent.put.bind(parent);
    case 'DELETE':
      return parent.delete.bind(parent);
    default:
      return parent.get.bind(parent);
  }
};

const validate = (_rconfg, vconfig = {}) => {
  if (_rconfg.validate) {
    const vFn = _.get(vconfig, _rconfg.validate);
    if (vFn) {
      return (req, res, next) => {
        if (vFn.query) {
          validatez.create(vFn.query)(req.query);
        }
        if (vFn.params) {
          validatez.create(vFn.params)(req.params);
        }
        if (vFn.body) {
          validatez.create(vFn.body)(req.body);
        }
        next();
      };
    }
  }
  return (req, res, next) => {
    next();
  };
};

const jsonResp = (req, res) => res.json.bind(res);

const suffix = (fn, _rconfg, sconfig = {}) => {
  const ext = _rconfg.ext || 'json';
  return (req, res, next) => co(function* sup() {
    const data = yield fn(req, res);
    if (sconfig[ext]) {
      yield sconfig[ext](req, res)(data);
    } else {
      jsonResp(req, res)(data);
    }
  }).catch(next);
};

const _create = (parent, _rconfg, config) => {
  const path = _rconfg.path || '/';
  const routes = _rconfg.routes;
  const router = express.Router();
  const filters = filter(_rconfg, config.filters) || [];
  const mid = [];
  mid.push(...filters);
  if (routes) {
    _debug && console.log('add sup route', path);
    for (const rout of routes) {
      _create(router, rout, config);
    }
    mid.push(router);
    parent.use(path, ...mid);
  } else {
    const _method = getMethod(parent, _rconfg);
    const argz = [path];
    const validator = validate(_rconfg, config.validators);
    argz.push(validator);
    argz.push(...mid);
    const fn = _.get(config.routes, _rconfg.match);
    if (!fn) {
      throw new Error(`no_such_handle:${_rconfg.match}`);
    }
    const flush = suffix(fn, _rconfg, config.suffixs);
    argz.push(flush);
    _debug && console.log('add route', path);
    _method(...argz);
  }
};

exports.create = _create;
