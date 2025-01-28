import java.util.*;

public class Management{

  static LinkedList<String> a = new LinkedList<>();

  static Scanner sc = new Scanner(System.in);

  static int page = 0;

  public static void nextp(){

    if(a.size()<=1 || a.size()-1==page){

      System.out.println("No next page");

    }

    else{

      page++;

      open();

    }

  }

  public static void prevp(){

    if(a.size()<=1 || page==0){

      System.out.println("No previous page");

    }

    else{

      page--;

      open();

    }

  }

  public static void search(){

    System.out.print("Search: ");

    String s = sc.next();

    a.add(s);

    page = a.size()-1;

    open();

  }

  public static void open(){

    System.out.println("Opened: "+a.get(page));

  }

  public static void option(){

    while(true){

      System.out.print("<- or -> or search or exit: ");

      String s = sc.next();

      if(s.equals("<-")){

        prevp();

      }

      else if(s.equals("->")){

        nextp();

      }

      else if(s.equals("search")){

        search();

      }

      else if(s.equals("exit")){

        break;

      }

      else{

        System.out.println("Invalid choice");

      }

    }

  }

  public static void main(String[] args) {

    option();

  }

}