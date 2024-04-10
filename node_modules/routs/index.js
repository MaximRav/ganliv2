const express = require('./lib/express').create;

const swap = fn =>
  new Promise((resolve, reject) => {
    fn(req, res, (err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });

module.exports = { express, swap };
