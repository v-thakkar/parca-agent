// Copyright (c) 2022 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package kconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBpfConfig(t *testing.T) {

	/*	configPaths := []string{
		"testdata/ProcConfig.gz",
		"testdata/config-5.17.15-76051715-generic",
		"testdata/config",
	}*/

	testcases := []struct {
		name string
		path string
		//want    string
		//wantErr bool
	}{
		{
			name: "Config file with correct config",
			path: "testdata/procconfig.gz",
			//want: "",
		},
		{
			name: "Config file with missing option",
			path: "testdata/config-5.17.15-76051715-generic",
			//want:    "kernel config required for ebpf not found, Config Option:CONFIG_BPF_JIT",
			//wantErr: true,
		},
		{
			name: "Config file with disabled option",
			path: "testdata/config",
			//want:    "kernel config required for ebpf is disabled, Config Option:CONFIG_BPF_EVENTS",
			//wantErr: true,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {

			//check for the file read failures
			config, err := getConfig(tt.path)
			assert.Equal(t, err, nil)
			assert.NotEmpty(t, config)

			/*	isBPFEnabled, err := IsBPFEnabled(configPaths)

				if tt.wantErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				assert.NotEqual(t, tt.wantErr, isBPFEnabled)
				assert.Equal(t, tt.want, err)*/
		})
	}

}
