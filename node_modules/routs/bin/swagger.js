#!/usr/bin/env node

const escodegen = require('escodegen');
const u = require('./util');
const debug = require('debug');
const _ = require('lodash');
const fs = require('fs');
const path = require('path');

const LOG = debug('routs:log');
const ERR = debug('routs:err');


const OPTION = {
  comment: true,
  format: {
    indent: {
      style: '  ',
      base: 0,
      adjustMultilineComment: false,
    },
  },
};

const _generate = meta => escodegen.generate(meta, OPTION);


const curd = {
  type: 'VariableDeclaration',
  declarations: [
    {
      type: 'VariableDeclarator',
      id: {
        type: 'ObjectPattern',
        properties: [
          {
            type: 'Property',
            method: false,
            shorthand: true,
            computed: false,
            key: {
              type: 'Identifier',
              name: '_get',
            },
            kind: 'init',
            value: {
              type: 'Identifier',
              name: '_get',
            },
          },
          {
            type: 'Property',
            method: false,
            shorthand: true,
            computed: false,
            key: {
              type: 'Identifier',
              name: '_post',
            },
            kind: 'init',
            value: {
              type: 'Identifier',
              name: '_post',
            },
          },
          {
            type: 'Property',
            method: false,
            shorthand: true,
            computed: false,
            key: {
              type: 'Identifier',
              name: '_put',
            },
            kind: 'init',
            value: {
              type: 'Identifier',
              name: '_put',
            },
          },
          {
            type: 'Property',
            method: false,
            shorthand: true,
            computed: false,
            key: {
              type: 'Identifier',
              name: '_del',
            },
            kind: 'init',
            value: {
              type: 'Identifier',
              name: '_del',
            },
          },
        ],
      },
      init: {
        type: 'CallExpression',
        callee: {
          type: 'Identifier',
          name: 'require',
        },
        arguments: [
          {
            type: 'Literal',
            value: './util',
            raw: "'./util'",
          },
        ],
      },
    },
  ],
  kind: 'const',
};

const creator = {
  type: 'ExpressionStatement',
  expression: {
    type: 'AssignmentExpression',
    operator: '=',
    left: {
      type: 'MemberExpression',
      object: {
        type: 'Identifier',
        name: 'exports',
      },
      property: {
        type: 'Identifier',
        name: 'create',
      },
      computed: false,
    },
    right: {
      type: 'ArrowFunctionExpression',
      id: null,
      generator: false,
      expression: false,
      params: [
        {
          type: 'Identifier',
          name: 'api',
        },
      ],
      body: {
        type: 'BlockStatement',
        body: [
          {
            type: 'ReturnStatement',
            argument: {
              type: 'ObjectExpression',
              properties: [/* add */],
            },
          },
        ],
      },
    },
  },
};

const method_map = {
  get: '_get',
  post: '_post',
  put: '_put',
  del: '_del',
  delete: '_del',
};

const param_create = (name) => {
  return {
    type: 'Identifier',
    name,
  };
};


const wrap = (route) => {
  const { method, desc, alias } = route;
  if (!alias) {
    throw new Error('routing config no alias');
  }
  const params = u.parseParams(route.path);

  let extra = {
    type: 'ObjectExpression',
    properties: [
      {
        type: 'Property',
        method: false,
        shorthand: false,
        computed: false,
        key: {
          type: 'Identifier',
          name: 'params',
        },
        value: {
          type: 'Identifier',
          name: 'query',
        },
        kind: 'init',
      },
    ],
  };
  const { exp, qur } = u.splitPath(route.path);

  switch (method) {
    case 'post':
    case 'put':
      extra = {
        type: 'Identifier',
        name: 'option',
      };
      params.push('option');
      break;
    default:
      params.push('query');
  }
  const args = [
    exp.length === 0
      ? u.createLiteral(qur[0])
      : {
        type: 'TemplateLiteral',
        expressions: exp.map(name => ({ type: 'Identifier', name })),
        quasis: qur.map(name => ({
          type: 'TemplateElement',
          value: { raw: name, cooked: name },
          tail: false,
        })),
      },
    extra,
  ];
  const rs = {
    type: 'ExpressionStatement',
    expression: {
      type: 'AssignmentExpression',
      operator: '=',
      left: {
        type: 'MemberExpression',
        object: {
          type: 'ThisExpression',
        },
        property: {
          type: 'Identifier',
          name: route.alias,
        },
        computed: false,
      },
      right: {
        type: 'ArrowFunctionExpression',
        id: null,
        generator: false,
        expression: true,
        params: params.map(p => ({ type: 'Identifier', name: p })),
        body: {
          type: 'CallExpression',
          callee: {
            type: 'MemberExpression',
            object: {
              type: 'Identifier',
              name: '$http',
            },
            property: {
              type: 'Identifier',
              name: method,
            },
            computed: false,
          },
          arguments: args,
        },
      },
    },
  };
  if (desc) {
    rs.leadingComments = u.createCommnet(desc);
  }
  return rs;
};

const motion = (opt) => {
  const { alias } = opt;
  let m = opt.method || 'get';
  m = m.toLowerCase();
  const getter = method_map[m];
  if (!alias) {
    return;
  }
  const params = u.parseParams(opt.path);
  const { exp, qur } = u.splitPath(opt.path);
  const _params = [];
  for (const p of params) {
    _params.push({
      type: 'Identifier',
      name: p,
    });
  }
  const ext = {
    type: 'Identifier',
  };
  if (m === 'put' || m === 'post') {
    _params.push({
      type: 'Identifier',
      name: 'data',
    });
    ext.name = 'data';
  } else {
    _params.push({
      type: 'Identifier',
      name: 'query',
    });
    ext.name = 'query';
  }
  qur.unshift('');
  exp.unshift('api');
  return {
    type: 'Property',
    method: true,
    shorthand: false,
    computed: false,
    key: {
      type: 'Identifier',
      name: alias,
    },
    kind: 'init',
    value: {
      type: 'FunctionExpression',
      id: null,
      generator: true,
      expression: false,
      params: _params,
      body: {
        type: 'BlockStatement',
        body: [
          {
            type: 'ReturnStatement',
            argument: {
              type: 'YieldExpression',
              delegate: false,
              argument: {
                type: 'CallExpression',
                callee: {
                  type: 'Identifier',
                  name: getter,
                },
                arguments: [
                  {
                    type: 'TemplateLiteral',
                    expressions: exp.map(name => ({ type: 'Identifier', name })),
                    quasis: qur.map((name, inx) => ({
                      type: 'TemplateElement',
                      value: { raw: name, cooked: name },
                      tail: inx === (qur.length - 1),
                    })),
                  },
                  ext,
                ],
              },
            },
          },
        ],
      },
    },
  };
};

const start = () => {
  if (process.argv.length < 3) {
    console.error('routs-es6: usage: routs-es6 [config] [target]');
    return;
  }
  const rc = path.resolve(process.argv[2]);

  // const target = path.resolve(process.argv[3]);

  if (!fs.existsSync(rc)) {
    ERR(`config file not exist: ${rc}`);
    throw new Error(`config file not exist: ${rc}`);
  }
  // if (!fs.existsSync(target)) {
  //   LOG(`create ng-service folder: ${target}`);
  //   fs.mkdirSync(target);
  // } else {
  //   LOG(`ng-service folder: ${target}`);
  // }
  const rs = {
    swagger: '2.0',
    info: {
      description: 'cyc-api',
      version: '1.0.0',
      title: 'changyoucai-sso-api',
      contact: {
        email: 'sankooc@163.com',
      },
      license: {
        name: 'Apache 2.0',
        url: 'http://www.apache.org/licenses/LICENSE-2.0.html',
      },
    },
    host: 'beta.changyoucai.com',
    basePath: '/',
    tags: [],
    schemes: ['http'],
    paths: [],
    securityDefinitions: [],
    definitions: [],
    externalDocs: [],
  };
  const cfg = module.require(rc);
  const rcons = u.parseRoute(cfg);
  for (const con of rcons) {
    LOG('service_name', con.name);
    console.log(con);
    rs.tags.push(con.name);
    // const _creator = _.cloneDeep(creator);
    // const _curd = _.cloneDeep(curd);
    // for (const rt of con.routes) {
    //   const fff = motion(rt);
    //   _creator.expression.right.body.body[0].argument.properties.push(fff);
    // }
    // const tpl = {
    //   type: 'Program',
    //   body: [_curd, _creator],
    //   sourceType: 'module',
    // };
    // const content = _generate(tpl);
    // console.log(content);
    // const _path = path.join(target, `${con.name}_gen.js`);
    // fs.writeFileSync(_path, content);
    // LOG(`create service [${con.name}]: ${_path}`);
  }
  console.dir(rs);
};


start();
