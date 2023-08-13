#include <stdio.h>
#include <stdlib.h>

struct TreeNode {
    int value;
    struct TreeNode** children;
    int numChildren;
};

struct TreeNode* createNode(int value, int numChildren) {
    struct TreeNode* node = (struct TreeNode*)malloc(sizeof(struct TreeNode));
    node->value = value;
    node->numChildren = numChildren;
    node->children = (struct TreeNode**)malloc(numChildren * sizeof(struct TreeNode*));
    return node;
}

void depthFirstTraversal(struct TreeNode* root) {
    if (root == NULL) {
        return;
    }

    struct TreeNode** stack = (struct TreeNode**)malloc(root->numChildren * sizeof(struct TreeNode*));
    int top = -1;

    stack[++top] = root;

    while (top >= 0) {
        struct TreeNode* node = stack[top--];
        printf("%d\n", node->value);  // Process the node however you want

        for (int i = node->numChildren - 1; i >= 0; i--) {
            stack[++top] = node->children[i];
        }
    }

    free(stack);
}

int main() {
    // Example usage
    struct TreeNode* root = createNode(1, 3);
    root->children[0] = createNode(2, 0);
    root->children[1] = createNode(3, 2);
    
    root->children[1]->children[0] = createNode(4, 0);
    root->children[1]->children[1] = createNode(5, 0);
    
    root->children[2] = createNode(6, 1);
    root->children[2]->children[0] = createNode(7, 0);

    depthFirstTraversal(root);

    // Clean up memory
    free(root);

    return 0;
}
