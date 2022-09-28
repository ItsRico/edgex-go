/*******************************************************************************
 * Copyright 2021 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 *******************************************************************************/

package setupacl

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/edgexfoundry/go-mod-core-contracts/v2/clients/logger"
	"github.com/edgexfoundry/go-mod-secrets/v2/pkg/types"
	"github.com/edgexfoundry/go-mod-secrets/v2/secrets/mocks"
	"github.com/stretchr/testify/require"
)

func TestCreateRole(t *testing.T) {
	ctx := context.Background()
	wg := &sync.WaitGroup{}
	lc := logger.MockLogger{}
	testSecretStoreToken := "test-secretstore-token"
	testSinglePolicy := []types.Policy{
		{
			ID:   "test-ID",
			Name: "test-name",
		},
	}
	testMultiplePolicies := []types.Policy{
		{
			ID:   "test-ID1",
			Name: "test-name1",
		},
		{
			ID:   "test-ID2",
			Name: "test-name2",
		},
	}

	testRoleWithNilPolicy := types.NewRegistryRole("testRoleSingle", types.ClientType, nil, true)
	testRoleWithEmptyPolicy := types.NewRegistryRole("testRoleSingle", types.ClientType, []types.Policy{}, true)
	testRoleWithSinglePolicy := types.NewRegistryRole("testRoleSingle", types.ClientType, testSinglePolicy, true)
	testRoleWithMultiplePolicies := types.NewRegistryRole("testRoleMultiple", types.ClientType, testMultiplePolicies, true)
	testEmptyRoleName := types.NewRegistryRole("", types.ManagementType, testSinglePolicy, true)
	testCreateRoleErr := errors.New("Failed to create role")
	testEmptyTokenErr := errors.New("required secret store token is empty")
	testEmptyRoleNameErr := errors.New("required registry role name is empty")
	tests := []struct {
		name                string
		secretstoreToken    string
		registryRole        types.RegistryRole
		creatRoleOkResponse bool
		expectedErr         error
	}{
		{"Good:create role with single policy ok", testSecretStoreToken, testRoleWithSinglePolicy, true, nil},
		{"Good:create role with multiple policies ok", testSecretStoreToken, testRoleWithMultiplePolicies, true, nil},
		{"Good:create role with empty policy ok", testSecretStoreToken, testRoleWithEmptyPolicy, true, nil},
		{"Good:create role with nil policy ok", testSecretStoreToken, testRoleWithNilPolicy, true, nil},
		{"Bad:create role bad response", testSecretStoreToken, testRoleWithSinglePolicy, false, testCreateRoleErr},
		{"Bad:empty secretstore token", "", testRoleWithMultiplePolicies, false, testEmptyTokenErr},
		{"Bad:empty role name", testSecretStoreToken, testEmptyRoleName, false, testEmptyRoleNameErr},
	}

	for _, tt := range tests {
		test := tt // capture as local copy
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// prepare test
			responseOpts := serverOptions{
				createRoleOk: test.creatRoleOkResponse,
			}
			testSrv := newRegistryTestServer(responseOpts)
			conf := testSrv.getRegistryServerConf(t)
			defer testSrv.close()

			command, err := NewCommand(ctx, wg, lc, conf, []string{})
			require.NoError(t, err)
			require.NotNil(t, command)
			require.Equal(t, "setupRegistryACL", command.GetCommandName())
			setupRegistryACL := command.(*cmd)
			setupRegistryACL.retryTimeout = 2 * time.Second

			secretClient := &mocks.SecretStoreClient{}

			secretClient.On("CreateRole", test.secretstoreToken,
				test.registryRole).
				Return(test.expectedErr).Once()
			err = test.expectedErr

			if test.expectedErr != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
