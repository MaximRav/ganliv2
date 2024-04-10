module.exports = {
  path: '/akb',
  routes: [
    {
      alias: 'common.hello',
      desc: 'sayHello',
      path: '/',
    },
    {
      path: '/user',
      routes: [
        {
          alias: 'common.print',
          desc: 'print something',
          path: '/:name',
          method: 'post',
        },
        {
          desc: 'print something2',
          path: '/:named',
          method: 'post',
        },
        {
          path: '/admin',
          routes: [
            {
              alias: 'admin.query',
              desc: 'admin querys',
              path: '/:bid',
            },
          ],
        },
      ],
    },
    {
      alias: 'system.excel',
      desc: 'download excel',
      path: '/excel',
    },
  ],
};