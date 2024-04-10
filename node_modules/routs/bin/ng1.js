#!/usr/bin/env node

const escodegen = require('escodegen');
const u = require('./util');
const fs = require('fs');
const path = require('path');
const chalk = require('chalk');

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

const generate = (angConf) => {
  const { desc, name, routes } = angConf;
  const _rts = routes.reduce((rs, routing) => {
    if (routing.alias) {
      const _r = wrap(routing);
      rs.push(_r);
    }
    return rs;
  }, []);
  if (!_rts.length) {
    throw new Error('no alias routing');
  }
  const meta = {
    type: 'Program',
    body: [],
    sourceType: 'module',
  };

  meta.body.push({
    type: 'ImportDeclaration',
    specifiers: [
      {
        type: 'ImportDefaultSpecifier',
        local: {
          type: 'Identifier',
          name: 'angular',
        },
      },
    ],
    leadingComments: u.createCommnet(desc, 'Block'),
    source: {
      type: 'Literal',
      value: 'angular',
      raw: "'angular'",
    },
  });

  meta.body.push({
    type: 'VariableDeclaration',
    declarations: [
      {
        type: 'VariableDeclarator',
        id: {
          type: 'Identifier',
          name: 'app',
        },
        init: {
          type: 'CallExpression',
          callee: {
            type: 'MemberExpression',
            object: {
              type: 'Identifier',
              name: 'angular',
            },
            property: {
              type: 'Identifier',
              name: 'module',
            },
            computed: false,
          },
          arguments: [
            {
              type: 'Literal',
              value: 'app',
              raw: "'app'",
            },
          ],
        },
      },
    ],
    kind: 'const',
  });

  const serviceName = {
    type: 'Literal',
    value: `$${name}Service`,
    raw: `'$${name}Service'`,
  };
  const service = {
    type: 'FunctionExpression',
    id: null,
    generator: false,
    expression: false,
    params: [
      {
        type: 'Identifier',
        name: '$http',
      },
    ],
    body: {
      type: 'BlockStatement',
      body: _rts,
    },
  };
  meta.body.push({
    type: 'ExpressionStatement',
    expression: {
      type: 'CallExpression',
      callee: {
        type: 'MemberExpression',
        object: {
          type: 'Identifier',
          name: 'app',
        },
        property: {
          type: 'Identifier',
          name: 'service',
        },
        computed: false,
      },
      arguments: [serviceName, service],
    },
  });
  return _generate(meta);
};

const start = () => {
  if (process.argv.length < 4) {
    throw new Error('arge');
  }
  const __path = path.resolve(process.argv[2]);

  const __target = path.resolve(process.argv[3]);

  if (!fs.existsSync(__path)) {
    throw new Error(`config file not exist: ${__path}`);
  }
  console.log('\r');
  if (!fs.existsSync(__target)) {
    console.log(chalk`  create ng-service folder: {green.bold ${__target}}`);
    fs.mkdirSync(__target);
  } else {
    console.log(chalk`  ng-service folder: {green.bold ${__target}}`);
  }
  const rc = require(__path);
  const rcons = u.parseRoute(rc);
  const indexContent = u.base();
  for (const conf of rcons) {
    const content = generate(conf);
    const _path = path.join(__target, `${conf.name}_gen.js`);
    fs.writeFileSync(_path, content);
    console.log(chalk`  create service [ {blue.bold $${conf.name}Service} ]: {yellow.bold ${_path}}`);
    indexContent.body.push(u.defRequire(`./${conf.name}_gen.js`));
  }
  const inxPath = path.join(__target, 'index.js');
  if (!fs.existsSync(inxPath)) {
    console.log(chalk`  create index {yellow.bold ${inxPath}}`);
    fs.writeFileSync(inxPath, _generate(indexContent));
  }
  console.log('\r');
};

start();
