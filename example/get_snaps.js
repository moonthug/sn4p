/**
 * Created by moonman
 */

///////////////////////////////////////////////////////////////////////////////
//
//
// DEPENDENCIES
//

// Package
var fs = require('fs');

// Library
var async = require('async');

// Internal
var Sn4p = require('../index');

///////////////////////////////////////////////////////////////////////////////
//
//
// IMPLEMENTATION
//


var options = {
    google: {
        email       : '',
        password    : ''
    },
    snapchat: {
        username    : '',
        password    : ''
    }
};

var sn4p = new Sn4p(options);

async.waterfall([
    // Login
    function(next) {
        sn4p.login(next);
    },

    // Get Snaps
    function(updates, next) {
        sn4p.getSnaps(next);
    },

    // Process
    function(snaps, next) {
        async.mapSeries(snaps, sn4p.getMedia.bind(sn4p), next);
    },

    // Media
    function(medias, next) {
        console.dir(medias);
    }
]);

