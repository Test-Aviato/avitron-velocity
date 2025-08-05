# FAST stage 3

<!-- markdownlint-disable MD036 -->

## Properties

*additional properties: false*

- ⁺**short_name**: *string*
- ⁺**environment**: *string*
  <br>*enum: ['dev', 'prod']*
- **cicd_config**: *object*
  <br>*additional properties: false*
  - ⁺**identity_provider**: *string*
  - ⁺**repository**: *object*
    <br>*additional properties: false*
    - ⁺**name**: *string*
    - **branch**: *string*
    - **type**: *string*
      <br>*default: github*, *enum: ['github', 'gitlab']*
  - **workflows_config**: *object*
    <br>*additional properties: false*
    - **extra_files**: *array*
      - items: *string*
- **folder_config**: *object*
  <br>*additional properties: false*
  - ⁺**name**: *string*
  - **parent_id**: *string*
  - **tag_bindings**: *object*
    <br>*additional properties: false*
    - **`^[a-z0-9_-]+$`**: *string*
  - **iam**: *reference([iam](#refs-iam))*
  - **iam_bindings**: *reference([iam_bindings](#refs-iam_bindings))*
  - **iam_bindings_additive**: *reference([iam_bindings_additive](#refs-iam_bindings_additive))*
  - **iam_by_principals**: *reference([iam_by_principals](#refs-iam_by_principals))*
  - **org_policies**: *object*
    <br>*additional properties: false*
    - **`^[a-z]+\.`**: *object*
      - **inherit_from_parent**: *boolean*
      - **reset**: *boolean*
      - **rules**: *array*
        - items: *object*
          <br>*additional properties: false*
          - **allow**: *object*
            <br>*additional properties: false*
            - **all**: *boolean*
            - **values**: *array*
              - items: *string*
          - **deny**: *object*
            <br>*additional properties: false*
            - **all**: *boolean*
            - **values**: *array*
              - items: *string*
          - **enforce**: *boolean*
          - **condition**: *object*
            <br>*additional properties: false*
            - **description**: *string*
            - **expression**: *string*
            - **location**: *string*
            - **title**: *string*

## Definitions

- **iam**<a name="refs-iam"></a>: *object*
  <br>*additional properties: false*
  - **
