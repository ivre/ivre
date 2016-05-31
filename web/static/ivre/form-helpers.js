var formHelpers = angular.module("formHelpers", []);

formHelpers.directive("queryBuilder", function ($location) {
    return {
        restrict: "E",
        scope: {
            query_submit: '&onSubmit',
            on_load: '@onLoad',
            title: "@",
            filters: '=bindTo',
        },
        templateUrl: "templates/query-builder.html",

        controller: function ($scope) {
            $scope.new_filter = "";

            $scope.on_submit = function () {
                if ($scope.new_filter !== "") {
                    $scope.filters.push($scope.new_filter);
                    $scope.new_filter = "";
                }

                $scope.filters = $scope.filters.filter(function (elt) {
                    return elt !== "";
                });

                $scope.query_submit();
            };
            
            $scope.remove = function (idx) {
                $scope.filters.splice(idx, 1);
            };

            $scope.$parent.$eval($scope.on_load);
        }
    };
});

formHelpers.factory("hashSync", function ($location) {
    return {
        /**
         * watch_type is "ref", "collection" or "val"
         */
        sync: function (scope, attr_name, sync_key, watch_type) {
            if (watch_type === undefined) {
                watch_type = "ref";
            }

            loc_watch = function () {
                return $location.search()[sync_key];
            };

            loc_action = function() {
                if ($location.search()[sync_key]) {
                    scope[attr_name] = angular.fromJson(
                            $location.search()[sync_key], true);
                }
            };

            model_action = function () {
                $location.search(sync_key, angular.toJson(scope[attr_name]));
            };

            switch (watch_type) {
                case "collection":
                    scope.$watchCollection(loc_watch, loc_action);
                    scope.$watchCollection(attr_name, model_action);
                    break;
                case "val":
                    scope.$watch(loc_watch, loc_action, true);
                    scope.$watch(attr_name, model_action, true);
                    break;
                default:
                    scope.$watch(loc_watch, loc_action);
                    scope.$watch(attr_name, model_action);
                    break;
            }
        },
    };
});

