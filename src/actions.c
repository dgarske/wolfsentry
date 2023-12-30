/*
 * actions.c
 *
 * Copyright (C) 2021-2023 wolfSSL Inc.
 *
 * This file is part of wolfSentry.
 *
 * wolfSentry is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSentry is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "wolfsentry_internal.h"

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_ACTIONS_C

static inline int wolfsentry_action_key_cmp_1(const char *left_label, unsigned const int left_label_len, const char *right_label, unsigned const int right_label_len) {
    int ret;

    if (left_label_len >= right_label_len) {
        ret = memcmp(left_label, right_label, right_label_len);
        if ((ret == 0) && (left_label_len != right_label_len))
            ret = 1;
    } else {
        ret = memcmp(left_label, right_label, left_label_len);
        if (ret == 0)
            ret = -1;
    }

    WOLFSENTRY_RETURN_VALUE(ret);
}

static int wolfsentry_action_key_cmp(const struct wolfsentry_table_ent_header *left, const struct wolfsentry_table_ent_header *right) {
    return wolfsentry_action_key_cmp_1(
        ((const struct wolfsentry_action *)left)->label,
        ((const struct wolfsentry_action *)left)->label_len,
        ((const struct wolfsentry_action *)right)->label,
        ((const struct wolfsentry_action *)right)->label_len);
}

static wolfsentry_errcode_t wolfsentry_action_init_1(const char *label, int label_len, wolfsentry_action_flags_t flags, wolfsentry_action_callback_t handler, void *handler_arg, struct wolfsentry_action *action, size_t action_size) {
    if (label_len <= 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (action_size < sizeof *action + (size_t)label_len + 1)
        WOLFSENTRY_ERROR_RETURN(BUFFER_TOO_SMALL);

    memset(&action->header, 0, sizeof action->header);

    action->handler = handler;
    action->handler_arg = handler_arg;
    memcpy(action->label, label, (size_t)label_len);
    action->label[label_len] = 0;
    action->label_len = (byte)label_len;
    action->flags = action->flags_at_creation = flags;

    action->header.refcount = 1;
    action->header.id = WOLFSENTRY_ENT_ID_NONE;

    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_action_new_1(WOLFSENTRY_CONTEXT_ARGS_IN, const char *label, int label_len, wolfsentry_action_flags_t flags, wolfsentry_action_callback_t handler, void *handler_arg, struct wolfsentry_action **action) {
    size_t new_size;
    wolfsentry_errcode_t ret;

    if ((label_len == 0) || (label == NULL) || (handler == NULL) || (action == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (label_len > WOLFSENTRY_MAX_LABEL_BYTES)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    else if (label_len < 0) {
        label_len = (int)strlen(label);
        if (label_len > WOLFSENTRY_MAX_LABEL_BYTES)
            WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    }

    new_size = sizeof **action + (size_t)label_len + 1;

    if ((*action = (struct wolfsentry_action *)WOLFSENTRY_MALLOC(new_size)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    ret = wolfsentry_action_init_1(label, label_len, flags, handler, handler_arg, *action, new_size);
    if (ret < 0) {
        WOLFSENTRY_FREE(*action);
        *action = NULL;
    }
    WOLFSENTRY_ERROR_RERETURN(ret);
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_clone(
    struct wolfsentry_context *src_context,
#ifdef WOLFSENTRY_THREADSAFE
    struct wolfsentry_thread_context *thread,
#endif
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header **new_ent,
    wolfsentry_clone_flags_t flags)
{
    struct wolfsentry_action * const src_action = (struct wolfsentry_action * const)src_ent;
    struct wolfsentry_action ** const new_action = (struct wolfsentry_action ** const)new_ent;
    size_t new_size = sizeof *src_action + (size_t)(src_action->label_len) + 1;

    (void)src_context;

    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN_EX(src_context);
    WOLFSENTRY_HAVE_MUTEX_OR_RETURN_EX(dest_context);

    if ((*new_action = WOLFSENTRY_MALLOC_1(dest_context->hpi.allocator, new_size)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memcpy(*new_action, src_action, new_size);
    WOLFSENTRY_TABLE_ENT_HEADER_RESET(**new_ent);
    if (WOLFSENTRY_CHECK_BITS(flags, WOLFSENTRY_CLONE_FLAG_AS_AT_CREATION))
        (*new_action)->flags = (*new_action)->flags_at_creation;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_insert_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    wolfsentry_action_flags_t flags,
    wolfsentry_action_callback_t handler,
    void *handler_arg,
    wolfsentry_ent_id_t *id)
{
    struct wolfsentry_action *new = NULL;
    wolfsentry_errcode_t ret;

    WOLFSENTRY_MUTEX_OR_RETURN();

    if ((ret = wolfsentry_action_new_1(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, flags, handler, handler_arg, &new)) < 0)
        goto out;
    if ((ret = wolfsentry_id_allocate(WOLFSENTRY_CONTEXT_ARGS_OUT, &new->header)) < 0)
        goto out;
    if (id)
        *id = new->header.id;
    if ((ret = wolfsentry_table_ent_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, &new->header, &wolfsentry->actions->header, 1 /* unique_p */)) < 0) {
        ret = WOLFSENTRY_ERROR_RECODE(ret);
        goto out;
    }
    ret = WOLFSENTRY_ERROR_ENCODE(OK);

out:

    if (ret < 0) {
        if (new != NULL)
            WOLFSENTRY_FREE(new);
    }

    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_insert(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *label,
    int label_len,
    wolfsentry_action_flags_t flags,
    wolfsentry_action_callback_t handler,
    void *handler_arg,
    wolfsentry_ent_id_t *id)
{
    wolfsentry_errcode_t ret = wolfsentry_label_is_builtin(label, label_len);
    if (WOLFSENTRY_SUCCESS_CODE_IS(ret, YES))
        WOLFSENTRY_ERROR_RETURN(NOT_PERMITTED);
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_action_insert_1(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, flags, handler, handler_arg, id));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_delete(WOLFSENTRY_CONTEXT_ARGS_IN, const char *label, int label_len, wolfsentry_action_res_t *action_results) {
    wolfsentry_errcode_t ret;
    struct {
        struct wolfsentry_action action;
        byte buf[WOLFSENTRY_MAX_LABEL_BYTES+1];
    } target;
    struct wolfsentry_action *target_p = &target.action;

    if ((label_len == 0) || (label == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (label_len > WOLFSENTRY_MAX_LABEL_BYTES)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    else if (label_len < 0) {
        label_len = (int)strlen(label);
        if (label_len > WOLFSENTRY_MAX_LABEL_BYTES)
            WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    }

    ret = wolfsentry_action_init_1(label, label_len, WOLFSENTRY_ACTION_FLAG_NONE, NULL, NULL, &target.action, sizeof target);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    WOLFSENTRY_MUTEX_OR_RETURN();

    target.action.header.parent_table = &wolfsentry->actions->header;

    if ((ret = wolfsentry_table_ent_delete(WOLFSENTRY_CONTEXT_ARGS_OUT, (struct wolfsentry_table_ent_header **)&target_p)) < 0)
        goto out;

    ret = wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, target_p, action_results);

out:

    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_flush_all(WOLFSENTRY_CONTEXT_ARGS_IN) {
    wolfsentry_errcode_t ret;
    WOLFSENTRY_MUTEX_OR_RETURN();
    ret = wolfsentry_table_free_ents(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->actions->header);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_action_get_reference_1(WOLFSENTRY_CONTEXT_ARGS_IN, const struct wolfsentry_action *action_template, struct wolfsentry_action **action) {
    wolfsentry_errcode_t ret;
    struct wolfsentry_action *ret_action = (struct wolfsentry_action *)action_template;
    ret = wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &wolfsentry->actions->header, (struct wolfsentry_table_ent_header **)&ret_action);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    WOLFSENTRY_REFCOUNT_INCREMENT(ret_action->header.refcount, ret);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    *action = ret_action;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_get_reference(WOLFSENTRY_CONTEXT_ARGS_IN, const char *label, int label_len, struct wolfsentry_action **action) {
    struct wolfsentry_action *action_template;
    wolfsentry_errcode_t ret;
    if (label_len == 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (label_len < 0)
        label_len = (int)strlen(label);
    if (label_len > WOLFSENTRY_MAX_LABEL_BYTES)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    if ((action_template = (struct wolfsentry_action *)WOLFSENTRY_MALLOC(sizeof *action_template + (size_t)label_len)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    action_template->label_len = (byte)label_len;
    memcpy(action_template->label, label, (size_t)label_len);
    WOLFSENTRY_SHARED_OR_RETURN();
    ret = wolfsentry_action_get_reference_1(WOLFSENTRY_CONTEXT_ARGS_OUT, action_template, action);
    WOLFSENTRY_FREE(action_template);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_action *action, wolfsentry_action_res_t *action_results) {
    wolfsentry_errcode_t ret;
    wolfsentry_refcount_t refs_left;
    if ((action->header.parent_table != NULL) &&
        (action->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ACTION))
        WOLFSENTRY_ERROR_RETURN(WRONG_OBJECT);
    WOLFSENTRY_REFCOUNT_DECREMENT(action->header.refcount, refs_left, ret);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    if (refs_left > 0)
        WOLFSENTRY_RETURN_OK;
    WOLFSENTRY_FREE(action);
    if (action_results)
        WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED);
    WOLFSENTRY_RETURN_OK;
}

const char *wolfsentry_action_get_label(const struct wolfsentry_action *action)
{
    return action ? action->label : (const char *)action;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_get_flags(
    struct wolfsentry_action *action,
    wolfsentry_action_flags_t *flags)
{
    *flags = action->flags;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_action_update_flags(
    struct wolfsentry_action *action,
    wolfsentry_action_flags_t flags_to_set,
    wolfsentry_action_flags_t flags_to_clear,
    wolfsentry_action_flags_t *flags_before,
    wolfsentry_action_flags_t *flags_after)
{
    WOLFSENTRY_ATOMIC_UPDATE_FLAGS(action->flags, flags_to_set, flags_to_clear, flags_before, flags_after);
    WOLFSENTRY_RETURN_OK;
}

static inline int wolfsentry_action_list_find_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    struct wolfsentry_action *action,
    struct wolfsentry_action_list_ent **action_list_ent)
{
    struct wolfsentry_list_ent_header *i;
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    for (wolfsentry_list_ent_get_first(&action_list->header, &i);
         i;
         wolfsentry_list_ent_get_next(&action_list->header, &i)) {
    if (((struct wolfsentry_action_list_ent *)i)->action == action)
            break;
    }
    if (i) {
        if (action_list_ent)
            *action_list_ent = (struct wolfsentry_action_list_ent *)i;
        WOLFSENTRY_RETURN_OK;
    } else
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
}

static inline int wolfsentry_action_list_append_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    struct wolfsentry_action *action)
{
    struct wolfsentry_action_list_ent *new;
    if (wolfsentry_action_list_find_1(WOLFSENTRY_CONTEXT_ARGS_OUT, action_list, action, NULL /* action_list_ent */) >= 0)
        WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);
    if ((new  = (struct wolfsentry_action_list_ent *)WOLFSENTRY_MALLOC(sizeof *new)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    new->action = action;
    wolfsentry_list_ent_append(&action_list->header, &new->header);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_append(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    const char *label,
    int label_len)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_action *action;

    WOLFSENTRY_MUTEX_OR_RETURN();

    ret = wolfsentry_action_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, &action);
    WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
    if ((ret = wolfsentry_action_list_append_1(WOLFSENTRY_CONTEXT_ARGS_OUT, action_list, action)) < 0) {
        int ret2 = wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, action, NULL /* action_results */);
        if (ret2 < 0)
            ret = ret2;
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

static inline int wolfsentry_action_list_prepend_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    struct wolfsentry_action *action)
{
    struct wolfsentry_action_list_ent *new;
    if (wolfsentry_action_list_find_1(WOLFSENTRY_CONTEXT_ARGS_OUT, action_list, action, NULL /* action_list_ent */) >= 0)
        WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);
    if ((new  = (struct wolfsentry_action_list_ent *)WOLFSENTRY_MALLOC(sizeof *new)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    new->action = action;
    wolfsentry_list_ent_prepend(&action_list->header, &new->header);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_prepend(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    const char *label,
    int label_len)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_action *action;

    WOLFSENTRY_MUTEX_OR_RETURN();

    if ((ret = wolfsentry_action_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, &action)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    if ((ret = wolfsentry_action_list_prepend_1(WOLFSENTRY_CONTEXT_ARGS_OUT, action_list, action)) < 0) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, action, NULL /* action_results */));
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

static inline wolfsentry_errcode_t wolfsentry_action_list_insert_after_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    struct wolfsentry_action *action,
    struct wolfsentry_action *point_action)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_action_list_ent *point = NULL, *new;

    if (wolfsentry_action_list_find_1(WOLFSENTRY_CONTEXT_ARGS_OUT, action_list, action, NULL /* action_list_ent */) >= 0)
        WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);
    if ((ret = wolfsentry_action_list_find_1(WOLFSENTRY_CONTEXT_ARGS_OUT, action_list, point_action, &point)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);
    if ((new  = (struct wolfsentry_action_list_ent *)WOLFSENTRY_MALLOC(sizeof *new)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    new->action = action;
    wolfsentry_list_ent_insert_after(&action_list->header, &point->header, &new->header);
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_insert_after(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    const char *label,
    int label_len,
    const char *point_label,
    int point_label_len)
{
    wolfsentry_errcode_t ret, ret2;
    struct wolfsentry_action *action, *point_action;

    WOLFSENTRY_MUTEX_OR_RETURN();

    if ((ret = wolfsentry_action_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, label, label_len, &action)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    if ((ret = wolfsentry_action_get_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, point_label, point_label_len, &point_action)) < 0) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, action, NULL /* action_results */));
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    ret = wolfsentry_action_list_insert_after_1(WOLFSENTRY_CONTEXT_ARGS_OUT, action_list, action, point_action);
    ret2 = wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, point_action, NULL /* action_results */);
    WOLFSENTRY_RERETURN_IF_ERROR(ret2);
    if (ret < 0) {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, action, NULL /* action_results */));
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    }
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_clone(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *src_action_list,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_action_list *dest_action_list,
    wolfsentry_clone_flags_t flags)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_list_ent_header *i;

    WOLFSENTRY_SHARED_OR_RETURN();
    ret = WOLFSENTRY_MUTEX_EX(dest_context);
    if (! WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
        WOLFSENTRY_UNLOCK_FOR_RETURN();
        WOLFSENTRY_ERROR_RERETURN(ret);
    }

    (void)flags;

    for (wolfsentry_list_ent_get_first(&src_action_list->header, &i);
         i && ((struct wolfsentry_action_list_ent *)i)->action;
         wolfsentry_list_ent_get_next(&src_action_list->header, &i))
    {
        struct wolfsentry_action *new_action = ((struct wolfsentry_action_list_ent *)i)->action;
        struct wolfsentry_action_list_ent *new_ale;
        if ((ret = wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &dest_context->actions->header, (struct wolfsentry_table_ent_header **)&new_action)) < 0) {
            ret = WOLFSENTRY_ERROR_RECODE(ret);
            goto out;
        }

        if ((new_ale = (struct wolfsentry_action_list_ent *)WOLFSENTRY_MALLOC_1(dest_context->hpi.allocator, sizeof *new_ale)) == NULL) {
            ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
            goto out;
        }

        new_ale->action = new_action;
        WOLFSENTRY_REFCOUNT_INCREMENT(new_action->header.refcount, ret);
        WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
        wolfsentry_list_ent_append(&dest_action_list->header, &new_ale->header);
    }
    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if (ret < 0)
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_list_delete_all(WOLFSENTRY_CONTEXT_ARGS_OUT_EX(dest_context), dest_action_list));

    WOLFSENTRY_UNLOCK_FOR_RETURN_EX(dest_context);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_delete(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list,
    const char *label,
    int label_len)
{
    struct wolfsentry_list_ent_header *i;

    if (label_len < 0)
        label_len = (int)strlen(label);

    WOLFSENTRY_MUTEX_OR_RETURN();

    for (wolfsentry_list_ent_get_first(&action_list->header, &i);
         i;
         wolfsentry_list_ent_get_next(&action_list->header, &i))
    {
        if (wolfsentry_action_key_cmp_1(
                ((struct wolfsentry_action_list_ent *)i)->action->label,
                ((struct wolfsentry_action_list_ent *)i)->action->label_len,
                label, (unsigned int)label_len)
            == 0)
            break;
    }

    if (i == NULL)
        WOLFSENTRY_ERROR_UNLOCK_AND_RETURN(ITEM_NOT_FOUND);

    wolfsentry_list_ent_delete(&action_list->header, i);
    WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, ((struct wolfsentry_action_list_ent *)i)->action, NULL /* action_results */));
    WOLFSENTRY_FREE(i);

    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_delete_all(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_action_list *action_list)
{
    struct wolfsentry_list_ent_header *i, *next;

    WOLFSENTRY_MUTEX_OR_RETURN();

    for (wolfsentry_list_ent_get_first(&action_list->header, &i);
         i;
         i = next)
    {
        next = i;
        wolfsentry_list_ent_get_next(&action_list->header, &next);

        wolfsentry_list_ent_delete(&action_list->header, i);
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, ((struct wolfsentry_action_list_ent *)i)->action, NULL /* action_results */));
        WOLFSENTRY_FREE(i);
    }

    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_list_dispatch(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    void *caller_arg,
    struct wolfsentry_event *action_event,
    struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_action_list_ent *i;
    struct wolfsentry_action_list *w_a_l = NULL;

    if (action_results == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (*action_results & WOLFSENTRY_ACTION_RES_STOP)
        WOLFSENTRY_ERROR_RETURN(ALREADY_STOPPED);

    WOLFSENTRY_HAVE_A_LOCK_OR_RETURN();

    switch (action_type) {
    case WOLFSENTRY_ACTION_TYPE_POST:
        w_a_l = &action_event->post_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_INSERT:
        w_a_l = &action_event->insert_action_list;

        if (WOLFSENTRY_CHECK_BITS(rule_route->flags, WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED))
            WOLFSENTRY_ERROR_RETURN(ALREADY);
        else {
            wolfsentry_route_flags_t flags_before;
            wolfsentry_route_flags_t flags_after;
            WOLFSENTRY_ATOMIC_UPDATE_FLAGS(
                rule_route->flags,
                (wolfsentry_route_flags_t)WOLFSENTRY_ROUTE_FLAG_INSERT_ACTIONS_CALLED,
                (wolfsentry_route_flags_t)WOLFSENTRY_ROUTE_FLAG_NONE,
                &flags_before,
                &flags_after);
        }

        break;
    case WOLFSENTRY_ACTION_TYPE_MATCH:
        w_a_l = &action_event->match_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_UPDATE:
        w_a_l = &action_event->update_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_DELETE:
        w_a_l = &action_event->delete_action_list;

        if (WOLFSENTRY_CHECK_BITS(rule_route->flags, WOLFSENTRY_ROUTE_FLAG_DELETE_ACTIONS_CALLED))
            WOLFSENTRY_ERROR_RETURN(ALREADY);
        else {
            wolfsentry_route_flags_t flags_before;
            wolfsentry_route_flags_t flags_after;
            WOLFSENTRY_ATOMIC_UPDATE_FLAGS(
                rule_route->flags,
                (wolfsentry_route_flags_t)WOLFSENTRY_ROUTE_FLAG_DELETE_ACTIONS_CALLED,
                (wolfsentry_route_flags_t)WOLFSENTRY_ROUTE_FLAG_NONE,
                &flags_before,
                &flags_after);
        }

        break;
    case WOLFSENTRY_ACTION_TYPE_DECISION:
        w_a_l = &action_event->decision_action_list;
        break;
    case WOLFSENTRY_ACTION_TYPE_NONE:
        break;
    }

    if (w_a_l == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (WOLFSENTRY_CHECK_BITS(wolfsentry->config.config.flags, WOLFSENTRY_EVENTCONFIG_FLAG_INHIBIT_ACTIONS) ||
        (action_event->config && WOLFSENTRY_CHECK_BITS(action_event->config->config.flags, WOLFSENTRY_EVENTCONFIG_FLAG_INHIBIT_ACTIONS)))
        WOLFSENTRY_RETURN_OK;

    for (i = (struct wolfsentry_action_list_ent *)w_a_l->header.head;
         i;
         i = (struct wolfsentry_action_list_ent *)i->header.next)
    {
        if (WOLFSENTRY_CHECK_BITS(i->action->flags, WOLFSENTRY_ACTION_FLAG_DISABLED))
            continue;
        if (! (rule_route->flags & WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_HITS))
            WOLFSENTRY_ATOMIC_INCREMENT(i->action->header.hitcount, 1);
#ifdef WOLFSENTRY_DEBUG_ACTIONS
        fprintf(stderr,"calling action %s for event %s and action type %u\n", wolfsentry_action_get_label(i->action), wolfsentry_event_get_label(trigger_event), (unsigned)action_type);
#endif
        if ((ret = i->action->handler(WOLFSENTRY_CONTEXT_ARGS_OUT, i->action, i->action->handler_arg, caller_arg, trigger_event, action_type, target_route, route_table, rule_route, action_results)) < 0)
            WOLFSENTRY_ERROR_RERETURN(ret);
        if (WOLFSENTRY_CHECK_BITS(*action_results, WOLFSENTRY_ACTION_RES_STOP))
            WOLFSENTRY_RETURN_OK;
    }
    WOLFSENTRY_RETURN_OK;
}

static wolfsentry_errcode_t wolfsentry_action_drop_reference_generic(WOLFSENTRY_CONTEXT_ARGS_IN, struct wolfsentry_table_ent_header *action, wolfsentry_action_res_t *action_results) {
    return wolfsentry_action_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, (struct wolfsentry_action *)action, action_results);
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_table_init(
    struct wolfsentry_action_table *action_table)
{
    WOLFSENTRY_TABLE_HEADER_RESET(action_table->header);
    action_table->header.cmp_fn = wolfsentry_action_key_cmp;
    action_table->header.free_fn = wolfsentry_action_drop_reference_generic;
    action_table->header.ent_type = WOLFSENTRY_OBJECT_TYPE_ACTION;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_table_clone_header(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)src_table;
    (void)dest_context;
    (void)dest_table;
    (void)flags;
    WOLFSENTRY_RETURN_OK;
}
