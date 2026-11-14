#include "tiny_gltf_v3.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static const uint64_t FUZZ_MEMORY_BUDGET = 64ULL * 1024 * 1024;
/* Cap per-accessor reads so a model with a huge accessor.count does not turn
 * every fuzz iteration into a multi-gigabyte allocation. */
static const uint64_t FUZZ_MAX_READ_VALUES = 4096;

typedef tg3_error_code (*tg3_fuzz_parse_fn)(tg3_model *, tg3_error_stack *,
    const uint8_t *, uint64_t, const char *, uint32_t, const tg3_parse_options *);

/* Exercises the merged-read entry points on a successfully parsed model.
 * Sparse merges, byte-offset/stride handling and normalization are only
 * reachable from these functions, so parsing alone would not cover them. */
static void tg3_fuzz_read_accessors(tg3_model *model) {
  uint32_t i;
  for (i = 0; i < model->accessors_count; ++i) {
    uint64_t value_count = 0;
    uint32_t components = 0;
    if (tg3_accessor_read_values(model, (int32_t)i, NULL, 0, &value_count,
                                 &components, NULL) == TG3_OK &&
        value_count > 0 && value_count <= FUZZ_MAX_READ_VALUES) {
      double *values = (double *)malloc((size_t)value_count * sizeof(double));
      if (values) {
        tg3_accessor_read_values(model, (int32_t)i, values, value_count,
                                 NULL, NULL, NULL);
        free(values);
      }
    }
    {
      uint64_t byte_count = 0, element_size = 0;
      if (tg3_accessor_read(model, (int32_t)i, NULL, 0, &byte_count,
                            &element_size, NULL) == TG3_OK &&
          byte_count > 0 && byte_count <= FUZZ_MAX_READ_VALUES * 16u) {
        uint8_t *bytes = (uint8_t *)malloc((size_t)byte_count);
        if (bytes) {
          tg3_accessor_read(model, (int32_t)i, bytes, byte_count, NULL, NULL, NULL);
          free(bytes);
        }
      }
    }
  }
  for (i = 0; i < model->meshes_count; ++i) {
    const tg3_mesh *mesh = &model->meshes[i];
    uint32_t pi;
    for (pi = 0; pi < mesh->primitives_count; ++pi) {
      const tg3_primitive *prim = &mesh->primitives[pi];
      uint32_t ai;
      for (ai = 0; ai < prim->attributes_count; ++ai) {
        uint64_t n = 0;
        uint32_t c = 0;
        tg3_read_vertex_attribute(model, mesh, pi,
                                  prim->attributes[ai].key.data,
                                  prim->attributes[ai].key.len,
                                  NULL, 0, &n, &c, NULL);
      }
      {
        uint64_t n = 0;
        if (tg3_read_primitive_indices(model, mesh, pi, NULL, 0, &n, NULL) == TG3_OK &&
            n > 0 && n <= FUZZ_MAX_READ_VALUES) {
          uint32_t *indices = (uint32_t *)malloc((size_t)n * sizeof(uint32_t));
          if (indices) {
            tg3_read_primitive_indices(model, mesh, pi, indices, n, NULL, NULL);
            free(indices);
          }
        }
      }
    }
  }
}

static void tg3_fuzz_run(tg3_fuzz_parse_fn fn, int parse_float32,
                         const uint8_t *data, size_t size) {
  tg3_model model;
  tg3_error_stack errors;
  tg3_parse_options opts;
  tg3_error_code err;

  tg3_error_stack_init(&errors);
  tg3_parse_options_init(&opts);
  opts.memory.memory_budget = FUZZ_MEMORY_BUDGET;
  opts.parse_float32 = parse_float32;

  err = fn(&model, &errors, data, (uint64_t)size, "", 0, &opts);
  if (err == TG3_OK) tg3_fuzz_read_accessors(&model);

  tg3_model_free(&model);
  tg3_error_stack_free(&errors);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) return 0;

  switch (data[0] % 4) {
    case 0: tg3_fuzz_run(tg3_parse_auto, 0, data + 1, size - 1); break;
    case 1: tg3_fuzz_run(tg3_parse,      0, data + 1, size - 1); break;
    case 2: tg3_fuzz_run(tg3_parse_glb,  0, data + 1, size - 1); break;
    case 3: tg3_fuzz_run(tg3_parse_auto, 1, data + 1, size - 1); break;
  }

  return 0;
}
