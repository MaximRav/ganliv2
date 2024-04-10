const assert = require('assert');

const u = require('../bin/util');
const rc = require('./rConfig');

describe('bdd', () => {
  it('util-spec', () => {
    {
      const rs = u.parseParams('/');
      assert.equal(rs.length, 0);
    }
    {
      const rs = u.parseParams('/api/user');
      assert.equal(rs.length, 0);
    }
    {
      const rs = u.parseParams('/api/user/:uid');
      assert.equal(rs.length, 1);
      assert.equal(rs[0], 'uid');
    }
    {
      const rs = u.parseParams('/api/user/:uid/volumn/:vid');
      assert.equal(rs.length, 2);
      assert.equal(rs[0], 'uid');
      assert.equal(rs[1], 'vid');
    }
    {
      const rs = u.splitPath('/');
      assert.equal(rs.exp.length, 0);
      assert.equal(rs.qur.length, 1);
      assert.equal(rs.qur[0], '/');
    }
    {
      const rs = u.splitPath('/api/user');
      assert.equal(rs.exp.length, 0);
      assert.equal(rs.qur.length, 1);
      assert.equal(rs.qur[0], '/api/user');
    }
    {
      const rs = u.splitPath('/api/user/:uid');
      assert.equal(rs.exp.length, 1);
      assert.equal(rs.qur.length, 2);
      assert.equal(rs.qur[0], '/api/user/');
      assert.equal(rs.qur[1], '');
      assert.equal(rs.exp[0], 'uid');
    }
    {
      const rs = u.splitPath('/api/user/:uid/volumn/:vid/ac');
      assert.equal(rs.exp.length, 2);
      assert.equal(rs.qur.length, 3);
      assert.equal(rs.qur[0], '/api/user/');
      assert.equal(rs.qur[1], '/volumn/');
      assert.equal(rs.qur[2], '/ac');
      assert.equal(rs.exp[0], 'uid');
      assert.equal(rs.exp[1], 'vid');
    }
  });
  it('route-parser', () => {
    const rs = u.parseRoute(rc);
    assert.equal(rs.length, 3);
    
    assert.equal(rs[0].routes.length, 2);
    assert.equal(rs[0].name, 'common');
    assert.equal(rs[0].routes[0].alias, 'hello');
    assert.equal(rs[0].routes[0].desc, 'sayHello');
    assert.equal(rs[0].routes[0].path, '/akb');
    assert.equal(rs[0].routes[0].method, 'get');

    assert.equal(rs[0].routes[1].alias, 'print');
    assert.equal(rs[0].routes[1].desc, 'print something');
    assert.equal(rs[0].routes[1].path, '/akb/user/:name');
    assert.equal(rs[0].routes[1].method, 'post');


    assert.equal(rs[1].routes.length, 1);
    assert.equal(rs[1].name, 'admin');
    assert.equal(rs[1].routes[0].alias, 'query');
    assert.equal(rs[1].routes[0].desc, 'admin querys');
    assert.equal(rs[1].routes[0].path, '/akb/user/admin/:bid');
    assert.equal(rs[1].routes[0].method, 'get');

    assert.equal(rs[2].routes.length, 1);
    assert.equal(rs[2].name, 'system');
    assert.equal(rs[2].routes[0].alias, 'excel');
    assert.equal(rs[2].routes[0].desc, 'download excel');
    assert.equal(rs[2].routes[0].path, '/akb/excel');
    assert.equal(rs[2].routes[0].method, 'get');
  });
});
