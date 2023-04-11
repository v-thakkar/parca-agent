package vdso

import (
	"debug/elf"
	"testing"

	"github.com/google/pprof/profile"
	"github.com/parca-dev/parca/pkg/symbol/symbolsearcher"
	"github.com/stretchr/testify/require"
)

func TestResolve(t *testing.T) {
	type args struct {
		validPath   string
		invalidPath string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
		addr    uint64
		mapping *profile.Mapping
	}{
		{
			name: "valid VDSO address",
			args: args{
				validPath:   "testdata/vdso_valid",
				invalidPath: "testdata/vdso_invalid",
			},
			want:    "_vdso_gettimeofday",
			wantErr: false,
			addr:    uint64(0x0000000000001000),
            mapping: &profile.Mapping{Start: 0x0000000000000000, Limit: 0x0000000000002000},
		},
		{
			name: "invalid VDSO address",
			args: args{
				validPath:   "testdata/vdso_valid",
				invalidPath: "testdata/vdso_invalid",
			},
			want:    "",
			wantErr: true,
			addr:    uint64(0xffffffffffffffff),
			mapping: &profile.Mapping{Start: 0xffffffffff600000, Limit: 0xffffffffff700000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary function to replace the NewCache method for testing.
			newTestCache := func() (*Cache, error) {
				var f string
				if tt.wantErr {
					f = tt.args.invalidPath
				} else {
					f = tt.args.validPath
				}

				elfFile, err := elf.Open(f)
				if err != nil {
					return nil, err
				}
				defer elfFile.Close()

				syms, err := elfFile.DynamicSymbols()
				if err != nil {
					return nil, err
				}
				return &Cache{searcher: symbolsearcher.New(syms), f: f}, nil
			}

			cache, err := newTestCache()
			require.NoError(t, err, "failed to create cache")

			symbol, err := cache.Resolve(tt.addr, tt.mapping)
			if tt.wantErr {
				require.Error(t, err, "expected error for invalid address")
			} else {
				require.NoError(t, err, "failed to resolve symbol")
			}
			require.Equal(t, tt.want, symbol, "symbol did not match expected value")
		})
	}
}
