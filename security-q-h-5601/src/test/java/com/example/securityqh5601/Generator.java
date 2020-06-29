//package com.example.securityqh5601;
//
//import org.junit.Test;
//import org.mybatis.generator.api.MyBatisGenerator;
//import org.mybatis.generator.config.Configuration;
//import org.mybatis.generator.config.xml.ConfigurationParser;
//import org.mybatis.generator.internal.DefaultShellCallback;
//
//import java.io.File;
//import java.util.ArrayList;
//import java.util.List;
//
///**
// * 逆向工程
// */
//public class Generator {
//
//    /**
//     * 注意，警惕，mmp,逆向工程不可重复运行第二次，如果要运行第二次，必须删除原来由逆向工程生成的所有文件，
//     * 否则sql语句的id和方法会重复，重复，重复，但是文件个数不会变化，，，，
//     * 运行不会报错，什么都没有，但是会找不到对应的mapper文件。
//     */
//    @Test
//    public void run() {
//        try {
//            this.generator();
//            System.out.println("成功");
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//    }
//
//    private void generator() throws Exception {
//        List<String> warnings = new ArrayList<String>();
//        boolean overwrite = true;
//        //加载配置文件
//        File configFile = new File("src/main/resources/mybatis/config/mybatis-generator.xml");
//        ConfigurationParser cp = new ConfigurationParser(warnings);
//        Configuration config = cp.parseConfiguration(configFile);
//        DefaultShellCallback callback = new DefaultShellCallback(overwrite);
//        MyBatisGenerator myBatisGenerator = new MyBatisGenerator(config, callback, warnings);
//        myBatisGenerator.generate(null);
//
//    }
//
//}
