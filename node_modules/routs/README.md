# routs

基于JSON的路由配置方案

## 目标

* 直观的路由配置
* 方便测试
* 自动生成前端服务模板(angular, redux ...) [WIP]

![mini](pic.png)

## 安装

` npm i routs `

## 配置

简单示例:  [demo](example)

yoeman scaffold: [asn](https://github.com/sankooc/generator-asn)


### 开始

```
const express = require('express');
const mroute = require('routs');
const app = express();

mroute.express(app, routerConfig, {
  routes,
  filters,
  validators,
  suffixs,
});
// routerConfig 路由配置文件
// routes: routing
// filters: 过滤器
// validators: 请求验证
// suffixs: 响应封装

```

### 路由配置

#### router config

```

{
  path: '/akb',
  routes: [], //routing config
  filters: [], // filters
}

```

#### routing config

```

{
  path: '/excel',
  match: 'print', 
  filters: ['auth'], //optional
  validate: 'vdata', //optional 
  method: 'post', //optional default is get 
  ext: 'excel', //optional default is json
  alias: 'download', // optional template service name
  desc: 'download excel file' // optional template service comments
}

```

| field     | value  | optional | routing/router |      desc       |   
|-----------|--------|----------|----------------|-----------------|
| path      | string |   false  |   true/true    |   routing path  |
| filters   | string |   true   |   true/true    | route filtering |
| routes    | array  |   false  |  false/true    |   sub routings  |
| match     | string |   false  |  true/false    | routing handle  |
| method    | string |   true   |  true/false    | routing method (post, put, get, delete, default is get) |
| ext       | string |   true   |  true/false    | response format |
| alias     | string |   true   |  true/false    | routing alias   |
| desc      | string |   true   |  true/false    | routing desc    |

生成模板服务时alias必须设置


### 请求验证

请求验证格式通过[validatez](https://github.com/sankooc/validatez)实现

### 过滤器

提供request,response. 返回结果通过co模块处理 

### routing

提供request,response. 返回结果通过co模块处理 


## 生成模板代码

### angular1 service

` ng1 [config file] [folder] `



## 工具方法

express中间件集成转换

```

const mroute = require('routs');

const mid = (req, res, next) => { ... } //express midware
exports.mid = mroute.swap(mid); // convert to routs-filter

```

## change log

### 1.03
 - 生成模板代码时alias字段成为可选项