/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

angular.module('dashboardApp')
    .controller('UserMfaController', UserMfaController);

UserMfaController.$inject = [
  '$http', '$scope', '$state', '$uibModalInstance', 'Utils', 'user', '$uibModal', 'toaster'
];

function UserMfaController(
    $http, $scope, $state, $uibModalInstance, Utils, user, $uibModal, toaster) {
  var userMfaCtrl = this;

  userMfaCtrl.$onInit = function() {
    console.log('UserMfaController onInit');
    getMfaSettings();
  };

  function getMfaSettings() {
    $http.get('/iam/multi-factor-settings/get-settings').then(function(response) {
      userMfaCtrl.authenticatorAppActive = response.data.authenticatorAppActive;
    });
  }

  userMfaCtrl.userToEdit = user;
  
  userMfaCtrl.yubiKeyActive = false;
  userMfaCtrl.enableAuthenticatorApp = enableAuthenticatorApp;
  userMfaCtrl.disableAuthenticatorApp = disableAuthenticatorApp;
  userMfaCtrl.enableYubiKey = enableYubiKey;
  userMfaCtrl.disableYubiKey = disableYubiKey;

  function enableAuthenticatorApp() {
    var modalInstance = $uibModal.open({
      templateUrl: '/resources/iam/apps/dashboard-app/templates/home/enable-authenticator-app.html',
      controller: 'EnableAuthenticatorAppController',
      controllerAs: 'authAppCtrl',
      resolve: {user: function() { return self.user; }}
    });

    modalInstance.result.then(function(msg) {
      return $uibModalInstance.close(msg);
    });
  }

  function disableAuthenticatorApp() {
    var modalInstance = $uibModal.open({
      templateUrl: '/resources/iam/apps/dashboard-app/templates/home/disable-authenticator-app.html',
      controller: 'DisableAuthenticatorAppController',
      controllerAs: 'authAppCtrl',
      resolve: {user: function() { return self.user; }}
    });

    modalInstance.result.then(function(msg) {
      return $uibModalInstance.close(msg);
    });
  }

  function enableYubiKey() {
    return true;
  }

  function disableYubiKey() {
    return true;
  }

  userMfaCtrl.dismiss = dismiss;
  userMfaCtrl.reset = reset;

  function reset() {
    console.log('reset form');

    userMfaCtrl.enabled = true;

    if ($scope.userMfaForm) {
      $scope.userMfaForm.$setPristine();
    }
  }

  userMfaCtrl.reset();

  function dismiss() { return $uibModalInstance.dismiss('Cancel'); }

  userMfaCtrl.message = '';

  userMfaCtrl.submit = function() {
    return $uibModalInstance.close('Updated settings');
    // ResetPasswordService
    //     .updatePassword(
    //         userMfaCtrl.user.currentPassword,
    //         userMfaCtrl.user.password)
    //     .then(function() { return $uibModalInstance.close('Password updated'); })
    //     .catch(function(error) {
    //       console.error(error);
    //       $scope.operationResult = Utils.buildErrorResult(error.data);
    //     });
  };
}