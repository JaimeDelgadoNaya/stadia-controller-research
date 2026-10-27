#pragma once
#include <stddef.h>
typedef void *QueueHandle_t;
static inline QueueHandle_t xQueueCreate(size_t n, size_t size) { (void)n; (void)size; return (void *)1; }
static inline int xQueueSendToBack(QueueHandle_t q, const void *p, int t) { (void)q; (void)p; (void)t; return 1; }
static inline int xQueueReceive(QueueHandle_t q, void *p, int t) { (void)q; (void)p; (void)t; return 1; }
