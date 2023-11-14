#include <iostream>

using namespace std;

const int N = 100010;

int h[N], idx;

void down(int x)
{
    int t = x, l = 2 * x, r = 2 * x + 1;
    if (l <= idx && h[l] < h[t]) t = l;
    if (r <= idx && h[r] < h[t]) t = r;
    if (t != x)
    {
        swap(h[t], h[x]);
        down(t);
    }
}

void up(int x)
{
    int t = x / 2;
    if (t == 0) return ;
    if (h[t] > h[x])
    {
        swap(h[t], h[x]);
        up(t);
    }
}

int main()
{
    int n;
    scanf("%d", &n);
    idx = 0;
    while (n -- )
    {
        char op[3];
        if (op[0] == 'I')
        {
            int x;
            scanf("%d", &x);
            h[++ idx] = x;
            up(idx);
        }
        else if (op[0] == 'P') printf("%d\n", h[1]);
        else if (op[0] == 'D' && op[1] == 'M') 
        {
            h[1] = h[idx --];
            down(1);
        }
        else if (op[0] == 'D')
        {
            int k;
            scanf("%d", &k);
            h[k] = h[idx --];
            down(k);
            up(k);
        }
        else 
        {
            int k, x;
            scanf("%d", &k, &x);
            h[k] = x;
            down(k);
            up(k);
        }
    }
    
    return 0;
}