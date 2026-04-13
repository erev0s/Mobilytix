'use strict';

Java.perform(function () {
  var classes = [];
  var seen = Object.create(null);

  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (seen[name]) return;
      seen[name] = true;

      classes.push({
        name: name,
        package: name.indexOf(".") > 0 ? name.substring(0, name.lastIndexOf(".")) : ""
      });
    },
    onComplete: function () {
      console.log(JSON.stringify({
        type: "loaded_classes",
        total: classes.length,
        classes: classes
      }));
    }
  });
});