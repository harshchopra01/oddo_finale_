class Binary_Search {
    // public static void main(String[] args) {
    //     int[] arr = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    //     int target = 5;
    //     int result = binarySearch(arr, target);
    //     if (result != -1) {
    //         System.out.println("Element found at index: " + result);
    //     } else {
    //         System.out.println("Element not found in the array.");
    //     }
    // }

    // public static int binarySearch(int[] arr, int target) {
    //     int left = 0;
    //     int right = arr.length - 1;

    //     while (left <= right) {
    //         int mid = left + (right - left) / 2;

    //         if (arr[mid] == target) {
    //             return mid; // Element found
    //         } else if (arr[mid] < target) {
    //             left = mid + 1; // Search in the right half
    //         } else {
    //             right = mid - 1; // Search in the left half
    //         }
    //     }

    //     return -1; // Element not found
    // }





// order-agnpostic binarysearch

    public static void main(String[] args) {
        int[] arr = {10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
        int target = 5;
        int result = binarySearch(arr, target);
        if (result != -1) {
            System.out.println("Element found at index: " + result);
        } else {
            System.out.println("Element not found in the array.");
        }
    }

    public static int binarySearch(int[] arr, int target) {
        int left = 0;
        int right = arr.length - 1;

        // find array sorted in ascending or descending order
        boolean isAsc;
        if(arr[left] < arr[right]) {
            isAsc = true;
        } else {
            isAsc = false;
        }


        while (left <= right) {
            int mid = left + (right - left) / 2;

            if (arr[mid] == target) {
                return mid; // Element found
            } 
        if(isAsc){
            if(arr[mid]<target){
                left = mid + 1;
            }
            else if(arr[mid]>target){
                    right = mid - 1;
                }
            }
        else{
            if(arr[mid]>target){
                left = mid + 1;
            }
            else if(arr[mid]<target){
                right = mid - 1;
            }
        }
        }
        return -1; // Element not found
    }


    

// returning next greater and smallest element  after the target element: celing of a number

public static void main(String[] args) {
    int [] arr =  {2,8,5,9,14,16,18};

}













}


